package services

import (
	"context"
	"sync"
	"testing"
	"time"

	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/kubevuln/adapters"
	v1 "github.com/kubescape/kubevuln/adapters/v1"
	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/kubevuln/repositories"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/require"
)

type blockedInventoryAcquirer struct {
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

type inventoryGenerationCreator struct{ *blockingSBOMCreator }

func (*inventoryGenerationCreator) GetMaxSBOMSize() int { return 1024 * 1024 }

func (p *blockedInventoryAcquirer) Acquire(_ context.Context, name, _ string, _ domain.RegistryOptions) (domain.SBOM, error) {
	p.once.Do(func() { close(p.started) })
	<-p.release
	return domain.SBOM{Name: name, Status: helpersv1.Completed, Content: &v1beta1.SyftDocument{}, Annotations: map[string]string{domain.SBOMImportSource: "oci-attestation-v1"}}, nil
}

func TestScanServiceSingleflightSeparatesInventoryEligibility(t *testing.T) {
	for _, kind := range []string{"workload", "instance"} {
		t.Run(kind, func(t *testing.T) {
			provider := &blockedInventoryAcquirer{started: make(chan struct{}), release: make(chan struct{})}
			var release sync.Once
			defer release.Do(func() { close(provider.release) })
			fallback := &blockingSBOMCreator{SBOMCreator: adapters.NewMockSBOMAdapter(false, false, false)}
			creator := v1.NewRegistrySBOMAdapter(&inventoryGenerationCreator{fallback}, provider)
			store := repositories.NewMemoryStorage(false, false)
			service := NewScanService(creator, store, adapters.NewMockCVEAdapter(), store, adapters.NewMockPlatform(false, nil), adapters.NewMockRelevancyAdapter(), false, false, true, false, false)
			registry := domain.ScanCommand{ImageSlug: "same-image", ImageHash: "sha256:1234567890ab", ImageTagNormalized: "registry.example/team/image:latest"}
			workload := registry
			if kind == "workload" {
				workload.Wlid = "wlid://cluster-test/namespace-default/deployment-test"
			} else {
				workload.InstanceID = "instance-test"
			}
			type result struct {
				sbom          domain.SBOM
				storeErr, err error
			}
			run := func(w domain.ScanCommand) <-chan result {
				done := make(chan result, 1)
				go func() {
					ctx := context.WithValue(context.Background(), domain.WorkloadKey{}, w)
					b, storeErr, err := service.getOrCreateSBOM(ctx, w)
					done <- result{b, storeErr, err}
				}()
				return done
			}
			registryDone := run(registry)
			select {
			case <-provider.started:
			case <-time.After(5 * time.Second):
				t.Fatal("registry import did not start")
			}
			// Keep the eligible leader blocked until the ineligible caller has completed.
			// A shared key would make that caller wait for (and receive) the imported SBOM.
			workloadDone := run(workload)
			select {
			case got := <-workloadDone:
				require.NoError(t, got.err)
				require.NoError(t, got.storeErr)
				require.NotNil(t, got.sbom.Content)
				require.False(t, got.sbom.Imported())
			case <-time.After(5 * time.Second):
				t.Fatal("workload joined the registry inventory flight")
			}
			release.Do(func() { close(provider.release) })
			select {
			case got := <-registryDone:
				require.NoError(t, got.err)
				require.NoError(t, got.storeErr)
				require.True(t, got.sbom.Imported())
			case <-time.After(5 * time.Second):
				t.Fatal("registry import did not finish")
			}
			fallback.mu.Lock()
			calls := fallback.calls
			fallback.mu.Unlock()
			require.Equal(t, 1, calls)
		})
	}
}

func TestSBOMSingleflightKeyInventoryEligibility(t *testing.T) {
	registry := domain.ScanCommand{ImageSlug: "same-image"}
	workload := registry
	workload.Wlid = "workload-a"
	instance := registry
	instance.InstanceID = "instance-a"
	opts := domain.RegistryOptions{Platform: "linux/amd64"}
	require.NotEqual(t, sbomSingleflightKey(registry, opts), sbomSingleflightKey(workload, opts))
	require.NotEqual(t, sbomSingleflightKey(registry, opts), sbomSingleflightKey(instance, opts))
	require.Equal(t, sbomSingleflightKey(workload, opts), sbomSingleflightKey(instance, opts), "generation-only callers can still share equivalent work")
}
