package repositories

import (
	"context"
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

	// Inject a local legacy statement (empty ID)
	legacyStmt := v1beta1.Statement{
		ID: "",
		Vulnerability: v1beta1.VexVulnerability{
			ID:   "CVE-LEGACY-1234",
			Name: "CVE-LEGACY-1234",
		},
		Products: []v1beta1.Product{
			{
				Component: v1beta1.Component{ID: "pkg:oci/some-image"},
				Subcomponents: []v1beta1.Subcomponent{
					{Component: v1beta1.Component{ID: "pkg:deb/debian/legacy-pkg@1.0"}},
				},
			},
		},
		Status:          v1beta1.Status(vex.StatusAffected),
		Justification:   "",
		ImpactStatement: "",
	}

	vexContainer.Spec.Statements = append(vexContainer.Spec.Statements, externalStmt, legacyStmt)
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
	foundLegacy := false
	for _, s := range vexContainerUpdated.Spec.Statements {
		if s.Vulnerability.Name == "CVE-LEGACY-1234" {
			foundLegacy = true
			assert.Equal(t, v1beta1.Status(vex.StatusNotAffected), s.Status, "Legacy statement should be reset by the reset loop")
			assert.Equal(t, v1beta1.Justification(vex.VulnerableCodeNotPresent), s.Justification, "Legacy statement should be reset by the reset loop")
		}
	}
	assert.True(t, foundLegacy, "Legacy statement should remain in the document")
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
