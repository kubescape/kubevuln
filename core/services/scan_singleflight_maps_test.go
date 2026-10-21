package services

import (
	"context"
	"reflect"
	"runtime"
	"sync"
	"testing"

	"github.com/kubescape/kubevuln/adapters"
	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/kubevuln/core/ports"
	"github.com/kubescape/kubevuln/repositories"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// annotatedSBOMCreator returns SBOMs that carry metadata, the way syft's does.
type annotatedSBOMCreator struct {
	ports.SBOMCreator
}

func (c *annotatedSBOMCreator) CreateSBOM(ctx context.Context, name, imageID, imageTag string, options domain.RegistryOptions) (domain.SBOM, error) {
	sbom, err := c.SBOMCreator.CreateSBOM(ctx, name, imageID, imageTag, options)
	sbom.Annotations = map[string]string{"shared": "yes"}
	sbom.Labels = map[string]string{"tier": "test"}
	return sbom, err
}

// Every caller sharing one SBOM creation gets maps of its own: the metadata is stamped
// per scan downstream, and two scans writing one map at the same time is a crash.
func TestScanService_SingleflightWaitersGetTheirOwnMaps(t *testing.T) {
	// One P, so every waiter has joined the shared creation before it is released (see
	// TestScanService_SingleflightSBOMFailure_ReportsEveryWaiter).
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(1))
	started := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	creator := &blockingSBOMCreator{
		SBOMCreator: &annotatedSBOMCreator{SBOMCreator: adapters.NewMockSBOMAdapter(false, false, false)},
		onStart: func() {
			once.Do(func() { close(started) })
			<-release
		},
	}
	service := NewScanService(
		creator,
		repositories.NewMemoryStorage(false, false),
		adapters.NewMockCVEAdapter(),
		repositories.NewMemoryStorage(false, false),
		adapters.NewMockPlatform(false, nil),
		adapters.NewMockRelevancyAdapter(),
		true, false, true, false, false,
	)
	workload := domain.ScanCommand{ImageSlug: "library/alpine:latest", ImageTagNormalized: "library/alpine:latest", ImageHash: "sha256:1234567890"}
	ctx := context.WithValue(context.Background(), domain.WorkloadKey{}, workload)

	const callers = 2
	var startWg, wg sync.WaitGroup
	startWg.Add(callers)
	wg.Add(callers)
	var mu sync.Mutex
	var sboms []domain.SBOM
	for i := 0; i < callers; i++ {
		go func() {
			defer wg.Done()
			startWg.Done()
			sbom, _, err := service.getOrCreateSBOM(ctx, workload)
			mu.Lock()
			defer mu.Unlock()
			require.NoError(t, err)
			sboms = append(sboms, sbom)
		}()
	}
	startWg.Wait()
	<-started
	close(release)
	wg.Wait()

	require.Len(t, sboms, callers)
	assert.Equal(t, 1, creator.calls, "both callers shared one creation")
	first, second := sboms[0], sboms[1]
	assert.Equal(t, map[string]string{"shared": "yes"}, first.Annotations)
	assert.NotEqual(t, reflect.ValueOf(first.Annotations).Pointer(), reflect.ValueOf(second.Annotations).Pointer(), "the annotations are not one map")
	assert.NotEqual(t, reflect.ValueOf(first.Labels).Pointer(), reflect.ValueOf(second.Labels).Pointer(), "the labels are not one map")
	first.Annotations["scan"] = "first"
	assert.NotContains(t, second.Annotations, "scan", "one caller's stamp does not reach the other")
	assert.Same(t, first.Content, second.Content, "the document itself is shared")
}
