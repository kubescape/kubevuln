package repositories

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/assert"
)

func TestMemoryStore_GetCVE(t *testing.T) {
	m := NewMemoryStorage(false, false)
	ctx := context.TODO()
	got, _ := m.GetCVE(ctx, "name", "", "", "")
	assert.Nil(t, got.Content)
	cve := domain.CVEManifest{
		Name:               "name",
		SBOMCreatorVersion: "",
		CVEScannerVersion:  "",
		CVEDBVersion:       "",
		Content:            &v1beta1.GrypeDocument{},
	}
	_ = m.StoreCVE(ctx, cve, false)
	got, _ = m.GetCVE(ctx, "name", "", "", "")
	assert.NotNil(t, got.Content)
}

func TestMemoryStore_GetSBOM(t *testing.T) {
	m := NewMemoryStorage(false, false)
	ctx := context.TODO()
	got, _ := m.GetSBOM(ctx, "name", "")
	assert.Nil(t, got.Content)
	sbom := domain.SBOM{
		Name:               "name",
		SBOMCreatorVersion: "",
		Status:             "",
		Content:            &v1beta1.SyftDocument{},
	}
	_ = m.StoreSBOM(ctx, sbom, false)
	got, _ = m.GetSBOM(ctx, "name", "")
	assert.NotNil(t, got.Content)
}

// TestMemoryStore_ConcurrentAccessIsRaceFree exercises every exported MemoryStore method from
// many goroutines at once. It exists to catch a regression of #852: MemoryStore's maps and
// counters used to have no synchronization, which `go test -race` never ran to catch because CI
// forced CGO_ENABLED=0. Concurrent access to a shared MemoryStore is not hypothetical -- the
// singleflight and worker-pool tests in core/services do exactly this -- so this test both
// stands on its own and documents why mu exists.
//
// It does not assert on the values read back: with concurrent writers racing on overlapping
// keys, which write "wins" is undefined by design. The only thing under test is that running
// every method concurrently is race- and panic-free (no "fatal error: concurrent map writes"),
// which `go test -race` verifies for us.
func TestMemoryStore_ConcurrentAccessIsRaceFree(t *testing.T) {
	m := NewMemoryStorage(false, false)
	ctx := context.TODO()

	const goroutines = 20
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func(i int) {
			defer wg.Done()

			// A mix of distinct and overlapping keys: overlapping keys are what actually
			// puts concurrent goroutines on the same map bucket.
			name := fmt.Sprintf("image-%d", i%3)

			ap := v1beta1.ContainerProfile{}
			ap.Namespace = "ns"
			ap.Name = name
			_ = m.StoreContainerProfile(ctx, ap)
			_, _ = m.GetContainerProfile(ctx, "ns", name)

			cve := domain.CVEManifest{Name: name, Content: &v1beta1.GrypeDocument{}}
			_ = m.StoreCVE(ctx, cve, false)
			_, _ = m.GetCVE(ctx, name, "", "", "")

			cvep := domain.CVEManifest{Name: name + "-relevant", Content: &v1beta1.GrypeDocument{}}
			_ = m.StoreCVESummary(ctx, cve, cvep, true)
			_, _ = m.GetCVESummary(ctx)

			_ = m.StoreCVESummaryStub(ctx, "stub-status")
			_ = m.CVESummaryStubs()

			sbom := domain.SBOM{Name: name, Content: &v1beta1.SyftDocument{}}
			_ = m.StoreSBOM(ctx, sbom, false)
			_, _ = m.GetSBOM(ctx, name, "")
			_ = m.SBOMStores()
			_ = m.DeleteSBOM(ctx, name)

			_ = m.StoreVEX(ctx, cve, cvep, false)
		}(i)
	}
	wg.Wait()
}
