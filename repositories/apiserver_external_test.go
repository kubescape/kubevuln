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
