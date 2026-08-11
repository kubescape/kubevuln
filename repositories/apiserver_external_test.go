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
