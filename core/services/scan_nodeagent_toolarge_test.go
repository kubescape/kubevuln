package services

import (
	"context"
	"errors"
	"maps"
	"testing"

	"github.com/armosec/armoapi-go/scanfailure"
	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/kubevuln/adapters"
	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/kubevuln/core/ports"
	"github.com/kubescape/kubevuln/repositories"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// semverSBOMCreator reports a real tool version: the mock's "Mock SBOM 1.0" is not semver, and
// semver.Compare treats two invalid versions as equal, which would skip the version check that
// node-agent's empty spec tool version fails in production.
type semverSBOMCreator struct {
	*adapters.MockSBOMAdapter
}

func (semverSBOMCreator) Version() string { return "v1.42.3" }

var _ ports.SBOMCreator = semverSBOMCreator{}

// TestScanService_NodeAgentTerminalSBOMs covers the SBOMs node-agent leaves behind when it
// gives up on an image, as its markSBOMStatus and size check write them: status and tool
// version annotations, no kubescape.io/status-reason, and an empty spec, so no spec tool
// version. With generation off, kubevuln must report their status and must not delete them,
// since node-agent only skips an image while its TooLarge SBOM exists.
func TestScanService_NodeAgentTerminalSBOMs(t *testing.T) {
	const ns = "kubescape"
	const slug = "imageslug"
	creator := semverSBOMCreator{adapters.NewMockSBOMAdapter(false, false, false)}
	creatorVersion := creator.Version()

	tests := []struct {
		name        string
		status      string
		annotations map[string]string
		toolVersion string
		wantReason  string
	}{
		{
			name:       "image too large",
			status:     helpersv1.TooLarge,
			wantReason: scanfailure.ReasonImageTooLarge,
		},
		{
			name:        "scanner crash loop",
			status:      helpersv1.TooLarge,
			annotations: map[string]string{domain.ScannerMemoryLimitAnnotationKey: "2147483648"},
			wantReason:  scanfailure.ReasonScannerOOMKilled,
		},
		{
			name:        "too large with current spec version",
			status:      helpersv1.TooLarge,
			toolVersion: creatorVersion,
			wantReason:  scanfailure.ReasonImageTooLarge,
		},
		{
			name:       "incomplete",
			status:     helpersv1.Incomplete,
			wantReason: scanfailure.ReasonSBOMIncomplete,
		},
	}
	flows := []struct {
		name     string
		validate func(*ScanService, context.Context, domain.ScanCommand) (context.Context, error)
		scan     func(*ScanService, context.Context) error
	}{
		{"ScanCVE", (*ScanService).ValidateScanCVE, (*ScanService).ScanCVE},
		{"ScanRegistry", (*ScanService).ValidateScanRegistry, (*ScanService).ScanRegistry},
	}

	for _, flow := range flows {
		for _, tt := range tests {
			t.Run(flow.name+"/"+tt.name, func(t *testing.T) {
				annotations := map[string]string{
					helpersv1.StatusMetadataKey:      tt.status,
					helpersv1.ToolVersionMetadataKey: creatorVersion,
				}
				maps.Copy(annotations, tt.annotations)
				stored := &v1beta1.SBOMSyft{
					ObjectMeta: metav1.ObjectMeta{Name: slug, Namespace: ns, Annotations: annotations},
				}
				stored.Spec.Metadata.Tool.Version = tt.toolVersion
				store := repositories.NewFakeAPIServerStorage(ns, stored)
				scanner := &recordingScanner{}
				s := NewScanService(
					creator, store,
					scanner, store,
					adapters.NewMockPlatform(false, nil), adapters.NewMockRelevancyAdapter(),
					true,  // storage
					false, // vexGeneration
					false, // sbomGeneration: node-agent owns SBOM generation
					false, false,
				)
				workload := domain.ScanCommand{
					ImageSlug:          slug,
					ImageHash:          "sha256:test",
					ImageTagNormalized: "k8s.gcr.io/kube-proxy:v1.24.3",
					Wlid:               "wlid://cluster-c/namespace-n/deployment-d",
				}
				ctx, err := flow.validate(s, context.Background(), workload)
				require.NoError(t, err)

				err = flow.scan(s, ctx)
				var scanErr *domain.ScanError
				require.True(t, errors.As(err, &scanErr), "got %v", err)
				assert.Equal(t, tt.wantReason, scanErr.Reason)
				assert.ErrorIs(t, err, domain.ErrIncompleteSBOM)
				assert.Empty(t, scanner.got, "a terminal SBOM reached the CVE scanner")

				_, getErr := store.StorageClient.SBOMSyfts(ns).Get(context.Background(), slug, metav1.GetOptions{})
				assert.NoError(t, getErr, "kubevuln deleted the SBOM node-agent owns")
			})
		}
	}
}
