package v1

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/grype/vulnerability/mock"
	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/kubevuln/config"
	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The manifest's maps are the scan's own. Before, ScanSBOM stamped the scan id into the
// SBOM's map and returned that very map, so two scans of one image sharing the SBOM
// through singleflight wrote the same map at the same time, and the manifest of one scan
// carried the other's scan id.
func TestGrypeAdapter_ScanSBOMLeavesTheSBOMsMapsAlone(t *testing.T) {
	g := NewGrypeAdapter("", config.CVEMatchingOn, nil)
	g.store, g.dbStatus = mock.VulnerabilityProvider(), &vulnerability.ProviderStatus{}
	content := &v1beta1.SyftDocument{SyftSource: v1beta1.SyftSource{Type: "directory", Metadata: json.RawMessage(`{"path":"/test"}`)}}
	annotations := map[string]string{"shared": "yes"}
	labels := map[string]string{"tier": "test"}
	sbom := domain.SBOM{Name: "image", Annotations: annotations, Labels: labels, Content: content}
	scan := func(id string) domain.CVEManifest {
		report, err := g.ScanSBOM(context.WithValue(context.Background(), domain.ScanIDKey{}, id), sbom)
		require.NoError(t, err)
		return report
	}

	first, second := scan("scan-a"), scan("scan-b")

	assert.Equal(t, map[string]string{"shared": "yes"}, annotations, "the SBOM's annotations are unchanged")
	assert.Equal(t, "scan-a", first.Annotations[helpersv1.ScanIdMetadataKey])
	assert.Equal(t, "scan-b", second.Annotations[helpersv1.ScanIdMetadataKey], "each manifest keeps its own scan id")
	assert.Equal(t, "yes", first.Annotations["shared"], "the SBOM's annotations are carried over")
	assert.Equal(t, string(config.CVEMatchingOn), first.Annotations[CVEMatchingModeMetadataKey])
	first.Labels["only"] = "first"
	assert.Equal(t, map[string]string{"tier": "test"}, labels, "the manifest's labels are a copy")
	assert.NotContains(t, second.Labels, "only")

	bare, err := g.ScanSBOM(context.WithValue(context.Background(), domain.ScanIDKey{}, "scan-c"), domain.SBOM{Name: "bare", Content: content})
	require.NoError(t, err)
	assert.Equal(t, "scan-c", bare.Annotations[helpersv1.ScanIdMetadataKey], "an SBOM without annotations still gets its stamp")
}
