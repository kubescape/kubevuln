package v1

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"

	sbomscanner "github.com/kubescape/kubevuln/pkg/sbomscanner/v1"
)

type mockScannerClientRace struct {
	sbomscanner.SBOMScannerClient
	healthCalls int32
}

func (m *mockScannerClientRace) Health(ctx context.Context) (string, bool, error) {
	atomic.AddInt32(&m.healthCalls, 1)
	return "test-version", true, nil
}

func TestSidecarVersion_CachingUnderConcurrency(t *testing.T) {
	mockClient := &mockScannerClientRace{}
	
	adapter := &SidecarSBOMAdapter{
		client: mockClient,
	}

	var wg sync.WaitGroup
	var readyWg sync.WaitGroup
	startCh := make(chan struct{})
	workers := 100
	
	// Launch many goroutines that constantly call Version() to hit the tiny race window
	// between singleflight.Do returning and versionMu being locked.
	for i := 0; i < workers; i++ {
		wg.Add(1)
		readyWg.Add(1)
		go func() {
			defer wg.Done()
			readyWg.Done()
			<-startCh
			
			for j := 0; j < 1000; j++ {
				version := adapter.Version()
				if version != "test-version" {
					t.Errorf("expected test-version, got %s", version)
				}
			}
		}()
	}

	readyWg.Wait()
	close(startCh)
	wg.Wait()

	calls := atomic.LoadInt32(&mockClient.healthCalls)
	if calls > 1 {
		t.Fatalf("expected Health to be called exactly 1 time due to caching, but was called %d times", calls)
	} else {
		t.Logf("Success! Health was called exactly 1 time.")
	}
}
