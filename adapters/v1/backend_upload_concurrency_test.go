package v1

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/armosec/armoapi-go/containerscan"
	v1 "github.com/armosec/armoapi-go/containerscan/v1"
	"github.com/armosec/armoapi-go/identifiers"
	"github.com/armosec/utils-go/httputils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// chunkStream feeds n one-vulnerability chunks on an unbuffered channel, the way
// SplitSlice2Chunks does, and closes done once the producer has handed off or been drained
// of every chunk.
func chunkStream(n int) (<-chan []containerscan.CommonContainerVulnerabilityResult, <-chan struct{}) {
	chunks := make(chan []containerscan.CommonContainerVulnerabilityResult)
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer close(chunks)
		for i := 0; i < n; i++ {
			chunks <- []containerscan.CommonContainerVulnerabilityResult{{}}
		}
	}()
	return chunks, done
}

func uploadTestReport() v1.ScanResultReport {
	return v1.ScanResultReport{
		Designators: identifiers.PortalDesignator{
			Attributes: map[string]string{identifiers.AttributeCustomerGUID: "00000000-0000-0000-0000-000000000000"},
		},
		Summary: &containerscan.CommonContainerScanSummaryResult{},
	}
}

func TestSendVulnerabilities_BoundsConcurrentPosts(t *testing.T) {
	const chunks = 100
	var inFlight, maxInFlight, posts atomic.Int32
	a := &BackendAdapter{
		backendClient: &MockBackendClient{
			HttpPostFunc: func(context.Context, httputils.IHttpClient, string, map[string]string, []byte, time.Duration) (*http.Response, error) {
				n := inFlight.Add(1)
				for {
					m := maxInFlight.Load()
					if n <= m || maxInFlight.CompareAndSwap(m, n) {
						break
					}
				}
				time.Sleep(5 * time.Millisecond)
				inFlight.Add(-1)
				posts.Add(1)
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(nil))}, nil
			},
		},
	}

	chunksChan, _ := chunkStream(chunks)
	errChan := make(chan error, 10)
	wg := &sync.WaitGroup{}
	a.sendVulnerabilities(context.Background(), chunksChan, "https://report.invalid", 1, chunks, "scan", uploadTestReport(), errChan, wg)
	wg.Wait()
	close(errChan)

	for err := range errChan {
		require.NoError(t, err)
	}
	assert.Equal(t, int32(chunks), posts.Load(), "every chunk is posted")
	assert.LessOrEqual(t, maxInFlight.Load(), int32(maxConcurrentReportPosts), "posts in flight never exceed the bound")
	assert.Greater(t, maxInFlight.Load(), int32(1), "posts still run concurrently")
}

func TestSendVulnerabilities_StopsWhenContextEndsWhileWaitingForSlot(t *testing.T) {
	var posts atomic.Int32
	a := &BackendAdapter{
		backendClient: &MockBackendClient{
			HttpPostFunc: func(context.Context, httputils.IHttpClient, string, map[string]string, []byte, time.Duration) (*http.Response, error) {
				posts.Add(1)
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(nil))}, nil
			},
		},
	}
	// Every slot is taken by another scan's posts. The context is live when dispatch
	// starts and ends only once the first chunk is waiting for a slot.
	slots := a.postSlots()
	for i := 0; i < maxConcurrentReportPosts; i++ {
		slots <- struct{}{}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var waits atomic.Int32
	a.postSlotWaitHook = func() {
		if waits.Add(1) == 1 {
			cancel()
		}
	}

	chunksChan, producerDone := chunkStream(20)
	errChan := make(chan error, 10)
	wg := &sync.WaitGroup{}
	dispatched := make(chan struct{})
	go func() {
		defer close(dispatched)
		a.sendVulnerabilities(ctx, chunksChan, "https://report.invalid", 1, 20, "scan", uploadTestReport(), errChan, wg)
	}()
	select {
	case <-dispatched:
	case <-time.After(5 * time.Second):
		t.Fatal("dispatch did not stop when the context ended during the wait for a slot")
	}
	wg.Wait()
	close(errChan)
	assert.Equal(t, int32(1), waits.Load(), "the first chunk waited for a slot; nothing after it did")

	select {
	case <-producerDone:
	case <-time.After(5 * time.Second):
		t.Fatal("chunk producer left blocked: the remaining chunks were not drained")
	}
	assert.Equal(t, int32(0), posts.Load(), "nothing is posted once the context has ended")
	var errs []error
	for err := range errChan {
		errs = append(errs, err)
	}
	require.Len(t, errs, 1, "the cancellation is reported once, not once per chunk")
	assert.ErrorIs(t, errs[0], context.Canceled)
}

func TestSendVulnerabilities_CancelledContextPostsNothingWithSlotsFree(t *testing.T) {
	var posts atomic.Int32
	a := &BackendAdapter{
		backendClient: &MockBackendClient{
			HttpPostFunc: func(context.Context, httputils.IHttpClient, string, map[string]string, []byte, time.Duration) (*http.Response, error) {
				posts.Add(1)
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(nil))}, nil
			},
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Repeated because a random choice between a free slot and ctx.Done would only show
	// up some of the time.
	for i := 0; i < 50; i++ {
		chunksChan, producerDone := chunkStream(20)
		errChan := make(chan error, 10)
		wg := &sync.WaitGroup{}
		a.sendVulnerabilities(ctx, chunksChan, "https://report.invalid", 1, 20, "scan", uploadTestReport(), errChan, wg)
		wg.Wait()
		close(errChan)
		<-producerDone
		var errs []error
		for err := range errChan {
			errs = append(errs, err)
		}
		require.Len(t, errs, 1, "the cancellation is reported once")
		assert.ErrorIs(t, errs[0], context.Canceled)
	}
	assert.Equal(t, int32(0), posts.Load(), "nothing is posted once the context has ended, even with slots free")
}
