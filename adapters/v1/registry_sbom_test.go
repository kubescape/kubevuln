package v1

import (
	"context"
	"errors"
	"testing"

	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/require"
)

type inventoryStub struct {
	result domain.SBOM
	err    error
	calls  int
}

func (s *inventoryStub) Acquire(context.Context, string, string, domain.RegistryOptions) (domain.SBOM, error) {
	s.calls++
	return s.result, s.err
}

type inventoryFallback struct{ inventoryStub }

func (s *inventoryFallback) CreateSBOM(ctx context.Context, n, id, tag string, o domain.RegistryOptions) (domain.SBOM, error) {
	return s.Acquire(ctx, n, id, o)
}
func (*inventoryFallback) Version() string        { return "local-version" }
func (*inventoryFallback) GetMaxImageSize() int64 { return 1024 }
func (*inventoryFallback) GetMaxSBOMSize() int    { return 1024 * 1024 }
func (*inventoryFallback) GetMemoryLimit() string { return "256Mi" }

func TestRegistrySBOMFallback(t *testing.T) {
	for _, reason := range []string{"absent", "wrong signer", "tampered", "wrong platform", "unsupported schema", "ambiguous", "timeout"} {
		t.Run(reason, func(t *testing.T) {
			p := &inventoryStub{err: errors.New(reason)}
			f := &inventoryFallback{inventoryStub{result: domain.SBOM{Content: &v1beta1.SyftDocument{}}}}
			a := NewRegistrySBOMAdapter(f, p)
			_, err := a.CreateSBOM(context.Background(), "image", "image", "", domain.RegistryOptions{})
			require.NoError(t, err)
			require.Equal(t, 1, f.calls)
			f.err = domain.ErrMockError
			_, err = a.CreateSBOM(context.Background(), "image", "image", "", domain.RegistryOptions{})
			require.ErrorIs(t, err, domain.ErrMockError)
		})
	}
}

func TestRegistrySBOMImportAndRuntimeFallback(t *testing.T) {
	p := &inventoryStub{result: domain.SBOM{Content: &v1beta1.SyftDocument{}, Status: helpersv1.Completed, SBOMCreatorVersion: "producer-version", Annotations: map[string]string{domain.SBOMImportSource: "oci-attestation-v1"}}}
	f := &inventoryFallback{inventoryStub{result: domain.SBOM{Content: &v1beta1.SyftDocument{}}}}
	a := NewRegistrySBOMAdapter(f, p)
	s, err := a.CreateSBOM(context.Background(), "image", "image", "", domain.RegistryOptions{})
	require.NoError(t, err)
	require.Equal(t, "producer-version", s.SBOMCreatorVersion)
	require.Zero(t, f.calls)
	require.Equal(t, "local-version", a.Version())
	ctx := context.WithValue(context.Background(), domain.WorkloadKey{}, domain.ScanCommand{Wlid: "runtime-workload"})
	_, err = a.CreateSBOM(ctx, "image", "image", "", domain.RegistryOptions{})
	require.NoError(t, err)
	require.Equal(t, 1, p.calls)
	require.Equal(t, 1, f.calls)
}

func TestRegistrySBOMRejectsEmptyFallback(t *testing.T) {
	a := NewRegistrySBOMAdapter(&inventoryFallback{}, nil)
	_, err := a.CreateSBOM(context.Background(), "image", "image", "", domain.RegistryOptions{})
	require.ErrorContains(t, err, "no inventory")
}
