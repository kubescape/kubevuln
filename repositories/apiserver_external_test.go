package repositories

import (
	"context"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/kubevuln/internal/tools"
	sev1beta1 "github.com/kubescape/kubevuln/pkg/securityexception/v1beta1"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/openvex/go-vex/pkg/vex"
)

func TestAPIServerStore_updateVEX_preservesExternalStatements(t *testing.T) {
	cveManifestFull := tools.FileToCVEManifest("testdata/nginx-cve.json")
	cveManifestFiltered := tools.FileToCVEManifest("testdata/nginx-cve-filtered.json")

	a := NewFakeAPIServerStorage("kubescape")
	ctx := context.TODO()
	workload := domain.ScanCommand{
		ImageHash:     "sha256:32fdf92b4e986e109e4db0865758020cb0c3b70d6ba80d02fe87bad5cc3dc228",
		InstanceID:    "apiVersion-apps/v1/namespace-kubescape/kind-ReplicaSet/name-kubevuln-65bfbfdcdd/containerName-kubevuln",
		Wlid:          "wlid://cluster-aaa/namespace-anyNamespaceJob/job-anyJob",
		ImageTag:      "registry.k8s.io/coredns/coredns:v1.10.1",
		ContainerName: "anyJobContName",
	}
	ctx = context.WithValue(ctx, domain.WorkloadKey{}, workload)

	require.NoError(t, a.StoreVEX(ctx, cveManifestFull, cveManifestFiltered, false))

	vexContainer, err := a.StorageClient.OpenVulnerabilityExchangeContainers(a.Namespace).Get(context.Background(), cveManifestFull.Name, metav1.GetOptions{})
	require.NoError(t, err)

	var target v1beta1.Statement
	for _, s := range vexContainer.Spec.Statements {
		if isLocalStatement(s.ID) && len(s.Products) > 0 && len(s.Products[0].Subcomponents) > 0 {
			target = s
			break
		}
	}
	require.NotEmpty(t, target.Vulnerability.Name)

	// Inject a purely external statement
	externalStmt := v1beta1.Statement{
		ID: "https://chainguard.dev/vex/statement/CVE-EXTERNAL-1234",
		Vulnerability: v1beta1.VexVulnerability{
			ID:   "CVE-EXTERNAL-1234",
			Name: "CVE-EXTERNAL-1234",
		},
		Products: []v1beta1.Product{
			{
				Component: v1beta1.Component{ID: "pkg:oci/some-image"},
				Subcomponents: []v1beta1.Subcomponent{
					{Component: v1beta1.Component{ID: "pkg:deb/debian/some-pkg@1.0"}},
				},
			},
		},
		Status:          v1beta1.Status(vex.StatusNotAffected),
		Justification:   v1beta1.Justification(vex.VulnerableCodeNotPresent),
		ImpactStatement: "External feed explicitly marked this as false positive",
	}

	// Inject an external statement without ID using a real vulnerability from the manifest
	externalStmtNoID := *target.DeepCopy()
	externalStmtNoID.ID = ""
	externalStmtNoID.Status = v1beta1.Status(vex.StatusAffected)
	externalStmtNoID.Justification = ""
	externalStmtNoID.ImpactStatement = "External feed assessed this one (no ID)"

	// Inject a true local kubescape statement
	localStmt := v1beta1.Statement{
		ID: "https://kubescape.io/vex/statement/CVE-LOCAL-1234/pkg%3Adeb%2Fdebian%2Flocal-pkg%401.0",
		Vulnerability: v1beta1.VexVulnerability{
			ID:   "CVE-LOCAL-1234",
			Name: "CVE-LOCAL-1234",
		},
		Products: []v1beta1.Product{
			{
				Component: v1beta1.Component{ID: "pkg:oci/some-image"},
				Subcomponents: []v1beta1.Subcomponent{
					{Component: v1beta1.Component{ID: "pkg:deb/debian/local-pkg@1.0"}},
				},
			},
		},
		Status:          v1beta1.Status(vex.StatusAffected),
		Justification:   "",
		ImpactStatement: "",
	}

	kept := make([]v1beta1.Statement, 0, len(vexContainer.Spec.Statements))
	for _, s := range vexContainer.Spec.Statements {
		if s.ID != target.ID {
			kept = append(kept, s)
		}
	}
	vexContainer.Spec.Statements = append(kept, externalStmt, externalStmtNoID, localStmt)
	_, err = a.StorageClient.OpenVulnerabilityExchangeContainers(a.Namespace).Update(context.Background(), vexContainer, metav1.UpdateOptions{})
	require.NoError(t, err)

	// Run updateVEX again via StoreVEX
	require.NoError(t, a.StoreVEX(ctx, cveManifestFull, cveManifestFiltered, false))

	vexContainerUpdated, err := a.StorageClient.OpenVulnerabilityExchangeContainers(a.Namespace).Get(context.Background(), cveManifestFull.Name, metav1.GetOptions{})
	require.NoError(t, err)

	foundExternal := false
	for _, s := range vexContainerUpdated.Spec.Statements {
		if s.ID == "https://chainguard.dev/vex/statement/CVE-EXTERNAL-1234" {
			foundExternal = true
			assert.Equal(t, externalStmt.Status, s.Status)
			assert.Equal(t, externalStmt.Justification, s.Justification)
			assert.Equal(t, externalStmt.ImpactStatement, s.ImpactStatement)
		}
	}
	assert.True(t, foundExternal, "External statement should remain in the document and be completely unmodified")
	foundExternalNoID := false
	foundLocalForTarget := false
	for _, s := range vexContainerUpdated.Spec.Statements {
		if s.Vulnerability.Name == target.Vulnerability.Name {
			if s.ID == "" {
				foundExternalNoID = true
				assert.Equal(t, v1beta1.Status(vex.StatusAffected), s.Status, "External statement without ID should be left untouched by the reset loop")
				assert.Equal(t, v1beta1.Justification(""), s.Justification, "External statement without ID should be left untouched by the reset loop")
				assert.Equal(t, "External feed assessed this one (no ID)", s.ImpactStatement, "ImpactStatement should remain unchanged")
			} else if isLocalStatement(s.ID) {
				foundLocalForTarget = true
			}
		}
	}
	assert.True(t, foundExternalNoID, "External statement without ID should remain in the document")
	assert.True(t, foundLocalForTarget, "A new local statement should have been generated alongside the ID-less external statement")

	foundLocal := false
	for _, s := range vexContainerUpdated.Spec.Statements {
		if s.Vulnerability.Name == "CVE-LOCAL-1234" {
			foundLocal = true
			assert.Equal(t, v1beta1.Status(vex.StatusNotAffected), s.Status, "True local statement should be reset by the reset loop")
			assert.Equal(t, v1beta1.Justification(vex.VulnerableCodeNotPresent), s.Justification, "True local statement should be reset by the reset loop")
		}
	}
	assert.True(t, foundLocal, "True local statement should remain in the document")
}

// #595 made updateVEX leave external statements alone, but the dedup that decides whether
// to append kubevuln's own statement still scans every statement rather than only the local
// ones. An external statement covering a vulnerability kubevuln also found therefore
// suppresses kubevuln's statement for it entirely, and since every assessment step
// (mark-affected, mark-ignored, reset-to-baseline) is local-only, that vulnerability ends up
// with no kubescape assessment in the document at all.
func TestAPIServerStore_updateVEX_externalStatementDoesNotSuppressLocalOne(t *testing.T) {
	cveManifestFull := tools.FileToCVEManifest("testdata/nginx-cve.json")
	cveManifestFiltered := tools.FileToCVEManifest("testdata/nginx-cve-filtered.json")

	a := NewFakeAPIServerStorage("kubescape")
	ctx := context.WithValue(context.TODO(), domain.WorkloadKey{}, domain.ScanCommand{
		ImageHash:     "sha256:32fdf92b4e986e109e4db0865758020cb0c3b70d6ba80d02fe87bad5cc3dc228",
		InstanceID:    "apiVersion-apps/v1/namespace-kubescape/kind-ReplicaSet/name-kubevuln-65bfbfdcdd/containerName-kubevuln",
		Wlid:          "wlid://cluster-aaa/namespace-anyNamespaceJob/job-anyJob",
		ImageTag:      "registry.k8s.io/coredns/coredns:v1.10.1",
		ContainerName: "anyJobContName",
	})

	require.NoError(t, a.StoreVEX(ctx, cveManifestFull, cveManifestFiltered, false))
	vexContainer, err := a.StorageClient.OpenVulnerabilityExchangeContainers(a.Namespace).Get(ctx, cveManifestFull.Name, metav1.GetOptions{})
	require.NoError(t, err)

	// Take one statement kubevuln generated, so the vulnerability and package are ones the
	// manifest really contains, and swap it for an external statement covering the same pair.
	var target v1beta1.Statement
	for _, s := range vexContainer.Spec.Statements {
		if isLocalStatement(s.ID) && len(s.Products) > 0 && len(s.Products[0].Subcomponents) > 0 {
			target = s
			break
		}
	}
	require.NotEmpty(t, target.Vulnerability.Name, "expected the first pass to generate statements")
	pkg := target.Products[0].Subcomponents[0].ID

	external := *target.DeepCopy()
	external.ID = "https://chainguard.dev/vex/statement/" + target.Vulnerability.Name
	external.Status = v1beta1.Status(vex.StatusAffected)
	external.ImpactStatement = "External feed assessed this one"

	kept := make([]v1beta1.Statement, 0, len(vexContainer.Spec.Statements))
	for _, s := range vexContainer.Spec.Statements {
		if s.ID != target.ID {
			kept = append(kept, s)
		}
	}
	vexContainer.Spec.Statements = append(kept, external)
	_, err = a.StorageClient.OpenVulnerabilityExchangeContainers(a.Namespace).Update(ctx, vexContainer, metav1.UpdateOptions{})
	require.NoError(t, err)

	require.NoError(t, a.StoreVEX(ctx, cveManifestFull, cveManifestFiltered, false))
	updated, err := a.StorageClient.OpenVulnerabilityExchangeContainers(a.Namespace).Get(ctx, cveManifestFull.Name, metav1.GetOptions{})
	require.NoError(t, err)

	foundLocal, foundExternal := false, false
	for _, s := range updated.Spec.Statements {
		if s.Vulnerability.Name != target.Vulnerability.Name {
			continue
		}
		if len(s.Products) == 0 || len(s.Products[0].Subcomponents) == 0 || s.Products[0].Subcomponents[0].ID != pkg {
			continue
		}
		if isLocalStatement(s.ID) {
			foundLocal = true
			continue
		}
		foundExternal = true
		assert.Equal(t, external.Status, s.Status, "the external statement must still be untouched")
		assert.Equal(t, external.ImpactStatement, s.ImpactStatement)
	}
	assert.True(t, foundExternal, "the external statement must survive")
	assert.True(t, foundLocal, "kubescape must still record its own assessment alongside the external one")
}

// newLocalStatement is the one place the shape of a statement kubevuln writes is defined,
// so it is worth pinning: createVEX and updateVEX each build one for a match and one for an
// ignored match, and all four used to spell it out.
func TestNewLocalStatement(t *testing.T) {
	m := v1beta1.Match{
		Vulnerability: v1beta1.Vulnerability{
			VulnerabilityMetadata: v1beta1.VulnerabilityMetadata{
				ID:          "CVE-2024-0001",
				DataSource:  "https://security-tracker.debian.org/tracker/CVE-2024-0001",
				Description: "a description",
			},
		},
		RelatedVulnerabilities: []v1beta1.VulnerabilityMetadata{{ID: "GHSA-aaaa"}, {ID: "EUVD-1"}},
		Artifact:               v1beta1.GrypePackage{PURL: "pkg:deb/debian/tar@1.29"},
	}

	stmt, err := newLocalStatement(m, "docker.io/library/nginx@sha256:abc")
	require.NoError(t, err)

	assert.True(t, isLocalStatement(stmt.ID), "the statement must be recognised as ours: %s", stmt.ID)
	assert.Contains(t, stmt.ID, url.PathEscape("CVE-2024-0001"))
	assert.Contains(t, stmt.ID, url.PathEscape("pkg:deb/debian/tar@1.29"))

	// The CVE goes in Name and the data source in ID, which is the mapping updateVEX's
	// normalization exists to repair on documents written the other way round.
	assert.Equal(t, "CVE-2024-0001", stmt.Vulnerability.Name)
	assert.Equal(t, "https://security-tracker.debian.org/tracker/CVE-2024-0001", stmt.Vulnerability.ID)
	assert.Equal(t, "a description", stmt.Vulnerability.Description)
	assert.Equal(t, []string{"GHSA-aaaa", "EUVD-1"}, stmt.Vulnerability.Aliases)

	require.Len(t, stmt.Products, 1)
	require.Len(t, stmt.Products[0].Subcomponents, 1)
	assert.Equal(t, "pkg:deb/debian/tar@1.29", stmt.Products[0].Subcomponents[0].ID)

	// The baseline every caller starts from; a suppression overwrites it wholesale.
	assert.Equal(t, v1beta1.Status(vex.StatusNotAffected), stmt.Status)
	assert.Equal(t, v1beta1.Justification(vex.VulnerableCodeNotPresent), stmt.Justification)
	assert.Equal(t, defaultLocalImpactStatement, stmt.ImpactStatement)
	assert.Empty(t, stmt.ActionStatement)
	assert.Empty(t, stmt.StatusNotes)
}

// Statements kubevuln wrote before #595 carry no ID, because #595 is what started setting
// one. #595 recognised them as ours via isLocalStatement's id == "" clause; #664 removed
// that clause so an external feed's ID-less statement would not be overwritten, which left
// every pre-#595 statement looking like another author's data: frozen by the reset loop and
// duplicated by the dedup, which now skips anything non-local.
func TestAPIServerStore_updateVEX_adoptsPre595StatementsWithoutIDs(t *testing.T) {
	cveManifestFull := tools.FileToCVEManifest("testdata/nginx-cve.json")
	cveManifestFiltered := tools.FileToCVEManifest("testdata/nginx-cve-filtered.json")

	a := NewFakeAPIServerStorage("kubescape")
	ctx := context.WithValue(context.TODO(), domain.WorkloadKey{}, domain.ScanCommand{
		ImageHash:     "sha256:32fdf92b4e986e109e4db0865758020cb0c3b70d6ba80d02fe87bad5cc3dc228",
		InstanceID:    "apiVersion-apps/v1/namespace-kubescape/kind-ReplicaSet/name-kubevuln-65bfbfdcdd/containerName-kubevuln",
		Wlid:          "wlid://cluster-aaa/namespace-anyNamespaceJob/job-anyJob",
		ImageTag:      "registry.k8s.io/coredns/coredns:v1.10.1",
		ContainerName: "anyJobContName",
	})

	require.NoError(t, a.StoreVEX(ctx, cveManifestFull, cveManifestFiltered, false))
	vexContainer, err := a.StorageClient.OpenVulnerabilityExchangeContainers(a.Namespace).Get(ctx, cveManifestFull.Name, metav1.GetOptions{})
	require.NoError(t, err)

	var target v1beta1.Statement
	for _, s := range vexContainer.Spec.Statements {
		if isLocalStatement(s.ID) && len(s.Products) > 0 && len(s.Products[0].Subcomponents) > 0 {
			target = s
			break
		}
	}
	require.NotEmpty(t, target.Vulnerability.Name)
	pkg := target.Products[0].Subcomponents[0].ID

	// Reshape it the way kubevuln stored it before #595: no ID, and carrying kubevuln's own
	// impact statement. A stale status stands in for one written by an earlier scan.
	legacy := *target.DeepCopy()
	legacy.ID = ""
	legacy.Status = v1beta1.Status(vex.StatusAffected)
	legacy.ImpactStatement = defaultLocalImpactStatement

	kept := make([]v1beta1.Statement, 0, len(vexContainer.Spec.Statements))
	for _, s := range vexContainer.Spec.Statements {
		if s.ID != target.ID {
			kept = append(kept, s)
		}
	}
	vexContainer.Spec.Statements = append(kept, legacy)
	_, err = a.StorageClient.OpenVulnerabilityExchangeContainers(a.Namespace).Update(ctx, vexContainer, metav1.UpdateOptions{})
	require.NoError(t, err)

	require.NoError(t, a.StoreVEX(ctx, cveManifestFull, cveManifestFiltered, false))
	updated, err := a.StorageClient.OpenVulnerabilityExchangeContainers(a.Namespace).Get(ctx, cveManifestFull.Name, metav1.GetOptions{})
	require.NoError(t, err)

	var forTarget []v1beta1.Statement
	for _, s := range updated.Spec.Statements {
		if s.Vulnerability.Name != target.Vulnerability.Name {
			continue
		}
		if len(s.Products) == 0 || len(s.Products[0].Subcomponents) == 0 || s.Products[0].Subcomponents[0].ID != pkg {
			continue
		}
		forTarget = append(forTarget, s)
	}

	require.Len(t, forTarget, 1, "our own older statement must be adopted, not left beside a fresh duplicate")
	assert.Equal(t, v1beta1.Status(vex.StatusNotAffected), forTarget[0].Status,
		"an adopted statement must be managed again, so the reset loop returns it to baseline")
}

// A statement can carry both legacy shapes at once: no ID, and the CVE in Vulnerability.ID
// with the data source in Name, from before that mapping was corrected. Adoption runs ahead
// of the normalization that repairs the mapping (it has to, since normalization only touches
// statements already recognised as ours), so it has to read the CVE from whichever field
// holds it or the ID it stamps is built from a URL and is wrong for good.
func TestAPIServerStore_updateVEX_adoptsStatementsWithBothLegacyShapes(t *testing.T) {
	cveManifestFull := tools.FileToCVEManifest("testdata/nginx-cve.json")
	cveManifestFiltered := tools.FileToCVEManifest("testdata/nginx-cve-filtered.json")

	a := NewFakeAPIServerStorage("kubescape")
	ctx := context.WithValue(context.TODO(), domain.WorkloadKey{}, domain.ScanCommand{
		ImageHash:     "sha256:32fdf92b4e986e109e4db0865758020cb0c3b70d6ba80d02fe87bad5cc3dc228",
		InstanceID:    "apiVersion-apps/v1/namespace-kubescape/kind-ReplicaSet/name-kubevuln-65bfbfdcdd/containerName-kubevuln",
		Wlid:          "wlid://cluster-aaa/namespace-anyNamespaceJob/job-anyJob",
		ImageTag:      "registry.k8s.io/coredns/coredns:v1.10.1",
		ContainerName: "anyJobContName",
	})

	require.NoError(t, a.StoreVEX(ctx, cveManifestFull, cveManifestFiltered, false))
	vexContainer, err := a.StorageClient.OpenVulnerabilityExchangeContainers(a.Namespace).Get(ctx, cveManifestFull.Name, metav1.GetOptions{})
	require.NoError(t, err)

	var target v1beta1.Statement
	for _, s := range vexContainer.Spec.Statements {
		if isLocalStatement(s.ID) && len(s.Products) > 0 && len(s.Products[0].Subcomponents) > 0 {
			target = s
			break
		}
	}
	require.NotEmpty(t, target.Vulnerability.Name)
	cve := target.Vulnerability.Name
	dataSource := target.Vulnerability.ID
	pkg := target.Products[0].Subcomponents[0].ID
	require.Contains(t, dataSource, "://", "the fixture's data source should be a URL")

	// No ID, and the CVE and data source the other way round.
	legacy := *target.DeepCopy()
	legacy.ID = ""
	legacy.Vulnerability.ID = cve
	legacy.Vulnerability.Name = dataSource
	legacy.ImpactStatement = defaultLocalImpactStatement

	kept := make([]v1beta1.Statement, 0, len(vexContainer.Spec.Statements))
	for _, s := range vexContainer.Spec.Statements {
		if s.ID != target.ID {
			kept = append(kept, s)
		}
	}
	vexContainer.Spec.Statements = append(kept, legacy)
	_, err = a.StorageClient.OpenVulnerabilityExchangeContainers(a.Namespace).Update(ctx, vexContainer, metav1.UpdateOptions{})
	require.NoError(t, err)

	require.NoError(t, a.StoreVEX(ctx, cveManifestFull, cveManifestFiltered, false))
	updated, err := a.StorageClient.OpenVulnerabilityExchangeContainers(a.Namespace).Get(ctx, cveManifestFull.Name, metav1.GetOptions{})
	require.NoError(t, err)

	var forTarget []v1beta1.Statement
	for _, s := range updated.Spec.Statements {
		if s.Vulnerability.Name != cve {
			continue
		}
		if len(s.Products) == 0 || len(s.Products[0].Subcomponents) == 0 || s.Products[0].Subcomponents[0].ID != pkg {
			continue
		}
		forTarget = append(forTarget, s)
	}

	require.Len(t, forTarget, 1, "the doubly-legacy statement must be adopted, not duplicated")
	assert.Equal(t, localStatementID(cve, pkg), forTarget[0].ID,
		"the stamped ID must be built from the CVE, not from whatever Name held before normalization")
	assert.Equal(t, dataSource, forTarget[0].Vulnerability.ID, "normalization must still repair the mapping")
}

// A statement last written while affected has no impact statement: the marking step blanks
// it and writes an action statement instead. That action statement is still wording of ours,
// and it arrived in #404, ten days before the IDs in #595, so a statement from that window
// carries one and no ID. Without recognising it, an affected statement stays unmanaged and
// gets duplicated on every rescan, the same failure this adoption exists to stop.
func TestAPIServerStore_updateVEX_adoptsAffectedStatementsByActionStatement(t *testing.T) {
	cveManifestFull := tools.FileToCVEManifest("testdata/nginx-cve.json")
	cveManifestFiltered := tools.FileToCVEManifest("testdata/nginx-cve-filtered.json")

	tests := []struct {
		name            string
		actionStatement func(purl string) string
	}{
		{"fallback wording", func(string) string { return defaultActionStatement }},
		{"named fix versions", func(purl string) string { return upgradeActionStatementPrefix(purl) + "1.2.3 or 1.3.0" }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := NewFakeAPIServerStorage("kubescape")
			ctx := context.WithValue(context.TODO(), domain.WorkloadKey{}, domain.ScanCommand{
				ImageHash:     "sha256:32fdf92b4e986e109e4db0865758020cb0c3b70d6ba80d02fe87bad5cc3dc228",
				InstanceID:    "apiVersion-apps/v1/namespace-kubescape/kind-ReplicaSet/name-kubevuln-65bfbfdcdd/containerName-kubevuln",
				Wlid:          "wlid://cluster-aaa/namespace-anyNamespaceJob/job-anyJob",
				ImageTag:      "registry.k8s.io/coredns/coredns:v1.10.1",
				ContainerName: "anyJobContName",
			})

			require.NoError(t, a.StoreVEX(ctx, cveManifestFull, cveManifestFiltered, false))
			vexContainer, err := a.StorageClient.OpenVulnerabilityExchangeContainers(a.Namespace).Get(ctx, cveManifestFull.Name, metav1.GetOptions{})
			require.NoError(t, err)

			var target v1beta1.Statement
			for _, s := range vexContainer.Spec.Statements {
				if isLocalStatement(s.ID) && len(s.Products) > 0 && len(s.Products[0].Subcomponents) > 0 {
					target = s
					break
				}
			}
			require.NotEmpty(t, target.Vulnerability.Name)
			pkg := target.Products[0].Subcomponents[0].ID

			// The shape markRelevantVulnerabilitiesAsAffectedInVex leaves behind, stored
			// before IDs existed.
			legacy := *target.DeepCopy()
			legacy.ID = ""
			legacy.Status = v1beta1.Status(vex.StatusAffected)
			legacy.Justification = ""
			legacy.ImpactStatement = ""
			legacy.ActionStatement = tt.actionStatement(pkg)

			kept := make([]v1beta1.Statement, 0, len(vexContainer.Spec.Statements))
			for _, s := range vexContainer.Spec.Statements {
				if s.ID != target.ID {
					kept = append(kept, s)
				}
			}
			vexContainer.Spec.Statements = append(kept, legacy)
			_, err = a.StorageClient.OpenVulnerabilityExchangeContainers(a.Namespace).Update(ctx, vexContainer, metav1.UpdateOptions{})
			require.NoError(t, err)

			require.NoError(t, a.StoreVEX(ctx, cveManifestFull, cveManifestFiltered, false))
			updated, err := a.StorageClient.OpenVulnerabilityExchangeContainers(a.Namespace).Get(ctx, cveManifestFull.Name, metav1.GetOptions{})
			require.NoError(t, err)

			var forTarget []v1beta1.Statement
			for _, s := range updated.Spec.Statements {
				if s.Vulnerability.Name != target.Vulnerability.Name {
					continue
				}
				if len(s.Products) == 0 || len(s.Products[0].Subcomponents) == 0 || s.Products[0].Subcomponents[0].ID != pkg {
					continue
				}
				forTarget = append(forTarget, s)
			}

			require.Len(t, forTarget, 1, "the affected statement must be adopted, not left beside a duplicate")
			assert.Equal(t, localStatementID(target.Vulnerability.Name, pkg), forTarget[0].ID)
			assert.Equal(t, v1beta1.Status(vex.StatusNotAffected), forTarget[0].Status,
				"once adopted it is managed again, so the reset loop returns it to baseline")
		})
	}
}

// An action statement that opens like ours but names a different package is another author's.
func TestIsOwnActionStatement(t *testing.T) {
	const purl = "pkg:deb/debian/tar@1.29"

	assert.True(t, isOwnActionStatement(defaultActionStatement, purl))
	assert.True(t, isOwnActionStatement(upgradeActionStatementPrefix(purl)+"1.30", purl))
	assert.False(t, isOwnActionStatement(upgradeActionStatementPrefix("pkg:deb/debian/other@1.0")+"2.0", purl))
	assert.False(t, isOwnActionStatement("Upgrade something to version 9", purl))
	assert.False(t, isOwnActionStatement("", purl))

	// The constant is ours whatever the subcomponent says, but the parameterised form is
	// only ours when it names this statement's own package, so an empty purl must not let
	// it through.
	assert.True(t, isOwnActionStatement(defaultActionStatement, ""))
	assert.False(t, isOwnActionStatement(upgradeActionStatementPrefix(purl)+"1.30", ""))
}

// Every ignored match in a manifest came from ApplySecurityExceptions, that being the only
// thing that writes IgnoredMatches, and Grype is given no VEX documents or ignore rules of
// its own. A backend-delivered exception policy never goes through buildPolicy, so it
// carries no sourceKind and its rule carries no SourceKind, which is not grounds for calling
// the suppression external.
func TestIgnoredMatchAssessment_AttributesBySource(t *testing.T) {
	match := v1beta1.Match{
		Vulnerability: v1beta1.Vulnerability{
			VulnerabilityMetadata: v1beta1.VulnerabilityMetadata{ID: "CVE-2021-44228"},
		},
	}

	tests := []struct {
		name  string
		rules []v1beta1.IgnoreRule
		want  string
	}{
		{
			name:  "CRD SecurityException",
			rules: []v1beta1.IgnoreRule{{Vulnerability: "CVE-2021-44228", SourceKind: "SecurityException", SourceName: "se/ns/name"}},
			want:  securityExceptionImpactStatement,
		},
		{
			name:  "cluster-scoped CRD",
			rules: []v1beta1.IgnoreRule{{Vulnerability: "CVE-2021-44228", SourceKind: "ClusterSecurityException", SourceName: "cse/name"}},
			want:  securityExceptionImpactStatement,
		},
		{
			// What buildIgnoreRule leaves behind for a backend-delivered policy: the
			// vulnerability id and nothing else.
			name:  "backend-delivered exception policy",
			rules: []v1beta1.IgnoreRule{{Vulnerability: "CVE-2021-44228"}},
			want:  cloudExceptionImpactStatement,
		},
		{
			// Grype states its own ignore rules against a package, which buildIgnoreRule
			// never sets. Nothing produces this today; #387 is what would.
			name:  "not ours",
			rules: []v1beta1.IgnoreRule{{Vulnerability: "CVE-2021-44228", Package: &v1beta1.IgnoreRulePackage{Name: "tar"}}},
			want:  externalIgnoreImpactStatement,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ignoredMatchAssessment(v1beta1.IgnoredMatch{Match: match, AppliedIgnoreRules: tt.rules})
			assert.Equal(t, tt.want, got.impactStatement)
			assert.Equal(t, v1beta1.Status(vex.StatusNotAffected), got.status,
				"all of these are suppressions, so the status is unchanged")
		})
	}
}

// A match can be suppressed by more than one SecurityException/ClusterSecurityException at
// once -- buildIgnoreRule (adapters/v1) writes one IgnoreRule per suppressing policy. An
// affected rule always requires an explicit, author-written actionStatement to suppress at
// all (shouldSuppress), so it must never be silently outranked by an automatic
// not_affected/fixed rule from a different, less specific exception -- whichever order they
// happen to be listed in.
func TestIgnoredMatchAssessment_MultipleExceptions_AffectedTakesPrecedence(t *testing.T) {
	match := v1beta1.Match{
		Vulnerability: v1beta1.Vulnerability{
			VulnerabilityMetadata: v1beta1.VulnerabilityMetadata{ID: "CVE-2021-44228"},
		},
	}
	affected := v1beta1.IgnoreRule{
		Vulnerability:   "CVE-2021-44228",
		SourceKind:      "SecurityException",
		SourceName:      "se/team-a/name",
		FixState:        string(sev1beta1.VulnerabilityStatusAffected),
		ImpactStatement: "WAF mitigation in place, ticket SEC-1234",
		Justification:   "will_not_fix",
	}
	notAffected := v1beta1.IgnoreRule{
		Vulnerability: "CVE-2021-44228",
		SourceKind:    "ClusterSecurityException",
		SourceName:    "cse/blanket-baseline",
		FixState:      string(sev1beta1.VulnerabilityStatusNotAffected),
		Justification: "vulnerable code not present",
	}

	tests := []struct {
		name  string
		rules []v1beta1.IgnoreRule
	}{
		{name: "affected listed first", rules: []v1beta1.IgnoreRule{affected, notAffected}},
		{name: "affected listed last", rules: []v1beta1.IgnoreRule{notAffected, affected}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ignoredMatchAssessment(v1beta1.IgnoredMatch{Match: match, AppliedIgnoreRules: tt.rules})

			assert.Equal(t, v1beta1.Status(vex.StatusAffected), got.status,
				"the risk-accepted exception must win regardless of list order")
			assert.Equal(t, "WAF mitigation in place, ticket SEC-1234", got.actionStatement,
				"the affected exception's real actionStatement must reach the export, not the other exception's")
			assert.Equal(t, "response: will_not_fix", got.statusNotes)
		})
	}
}

// Fixed also requires an explicit human decision (unlike the not_affected default), but it
// is not itself a risk acceptance the way affected is, so affected still takes precedence
// over it when both are present.
func TestIgnoredMatchAssessment_MultipleExceptions_AffectedBeatsFixed(t *testing.T) {
	match := v1beta1.Match{
		Vulnerability: v1beta1.Vulnerability{
			VulnerabilityMetadata: v1beta1.VulnerabilityMetadata{ID: "CVE-2021-44228"},
		},
	}
	rules := []v1beta1.IgnoreRule{
		{Vulnerability: "CVE-2021-44228", SourceKind: "ClusterSecurityException", FixState: string(sev1beta1.VulnerabilityStatusFixed)},
		{
			Vulnerability:   "CVE-2021-44228",
			SourceKind:      "SecurityException",
			FixState:        string(sev1beta1.VulnerabilityStatusAffected),
			ImpactStatement: "Compensating control documented in runbook",
		},
	}

	got := ignoredMatchAssessment(v1beta1.IgnoredMatch{Match: match, AppliedIgnoreRules: rules})

	assert.Equal(t, v1beta1.Status(vex.StatusAffected), got.status)
	assert.Equal(t, "Compensating control documented in runbook", got.actionStatement)
}

// With no affected rule among several matching exceptions, the first SE/CSE rule is used --
// the same behavior as before this fix, for the case that isn't a risk-acceptance conflict.
func TestIgnoredMatchAssessment_MultipleExceptions_NoAffected_FirstRuleWins(t *testing.T) {
	match := v1beta1.Match{
		Vulnerability: v1beta1.Vulnerability{
			VulnerabilityMetadata: v1beta1.VulnerabilityMetadata{ID: "CVE-2021-44228"},
		},
	}
	rules := []v1beta1.IgnoreRule{
		{Vulnerability: "CVE-2021-44228", SourceKind: "SecurityException", Justification: "first exception's reasoning"},
		{Vulnerability: "CVE-2021-44228", SourceKind: "ClusterSecurityException", Justification: "second exception's reasoning"},
	}

	got := ignoredMatchAssessment(v1beta1.IgnoredMatch{Match: match, AppliedIgnoreRules: rules})

	assert.Equal(t, v1beta1.Justification("first exception's reasoning"), got.justification)
}
