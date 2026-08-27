package controllers

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	wssc "github.com/armosec/armoapi-go/apis"
	"github.com/armosec/armoapi-go/scanfailure"
	"github.com/docker/docker/api/types/registry"
	"github.com/gammazero/workerpool"
	"github.com/gin-gonic/gin"
	"github.com/kubescape/k8s-interface/names"
	v1 "github.com/kubescape/kubevuln/adapters/v1"
	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/kubevuln/core/ports"
	"github.com/kubescape/kubevuln/core/services"
	"github.com/kubescape/kubevuln/internal/metrics"
	"github.com/kubescape/kubevuln/internal/tools"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHTTPController_Alive(t *testing.T) {
	c := HTTPController{}
	router := gin.Default()
	path := "/v1/liveness"
	router.GET(path, c.Alive)
	req, _ := http.NewRequest("GET", path, nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code, w.Code)
	assert.Equal(t, w.Body.String(), "{\"status\":200,\"title\":\"OK\"}", w.Body.String())
}

func TestHTTPController_GenerateSBOM(t *testing.T) {
	tests := []struct {
		name         string
		scanService  ports.ScanService
		expectedCode int
		expectedBody string
		yamlFile     string
	}{
		{
			name:         "invalid request",
			scanService:  services.NewMockScanService(true),
			expectedCode: http.StatusBadRequest,
			expectedBody: "{\"status\":400,\"title\":\"Bad Request\"}",
			yamlFile:     "../api/v1/testdata/scan-invalid.yaml",
		},
		{
			name:         "validation error",
			scanService:  services.NewMockScanService(false),
			expectedCode: http.StatusBadRequest,
			expectedBody: "{\"detail\":\"ImageHash=k8s.gcr.io/kube-proxy@sha256:c1b135231b5b1a6799346cd701da4b59e5b7ef8e694ec7b04fb23b8dbe144137\",\"status\":400,\"title\":\"Bad Request\"}",
			yamlFile:     "../api/v1/testdata/scan.yaml",
		},
		{
			name:         "ready",
			scanService:  services.NewMockScanService(true),
			expectedCode: http.StatusOK,
			expectedBody: "{\"detail\":\"ImageHash=k8s.gcr.io/kube-proxy@sha256:c1b135231b5b1a6799346cd701da4b59e5b7ef8e694ec7b04fb23b8dbe144137\",\"status\":200,\"title\":\"OK\"}",
			yamlFile:     "../api/v1/testdata/scan.yaml",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := HTTPController{
				scanService: tt.scanService,
				workerPool:  workerpool.New(1),
			}
			router := gin.Default()
			path := "/v1/generateSBOM"
			router.POST(path, c.GenerateSBOM)
			file, err := os.Open(tt.yamlFile)
			require.NoError(t, err)
			req, _ := http.NewRequest("POST", path, file)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			assert.Equal(t, tt.expectedCode, w.Code, w.Code)
			assert.Equal(t, tt.expectedBody, w.Body.String(), w.Body.String())
		})
	}
}

func TestHTTPController_Ready(t *testing.T) {
	tests := []struct {
		name         string
		scanService  ports.ScanService
		expectedCode int
		expectedBody string
	}{
		{
			name:         "not ready",
			scanService:  services.NewMockScanService(false),
			expectedCode: http.StatusServiceUnavailable,
			expectedBody: "{\"status\":503,\"title\":\"Service Unavailable\"}",
		},
		{
			name:         "ready",
			scanService:  services.NewMockScanService(true),
			expectedCode: http.StatusOK,
			expectedBody: "{\"status\":200,\"title\":\"OK\"}",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := HTTPController{scanService: tt.scanService}
			router := gin.Default()
			path := "/v1/readiness"
			router.GET(path, c.Ready)
			req, _ := http.NewRequest("GET", path, nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			assert.Equal(t, tt.expectedCode, w.Code, w.Code)
			assert.Equal(t, tt.expectedBody, w.Body.String(), w.Body.String())
		})
	}
}

func TestHTTPController_Diagnostics(t *testing.T) {
	tests := []struct {
		name         string
		diagnostics  func(ctx context.Context) domain.Diagnostics
		expectedBody string
	}{
		{
			name:         "not configured",
			diagnostics:  nil,
			expectedBody: `{"scanMode":"","sbomCreatorVersion":"","cveScannerVersion":"","cveDBVersion":"","scanTimeout":"","scannerReadinessTimeout":"","storageEnabled":false,"riskAcceptanceEnabled":false,"queueDepth":0}`,
		},
		{
			name: "sidecar mode with storage and risk acceptance enabled",
			diagnostics: func(context.Context) domain.Diagnostics {
				return domain.Diagnostics{
					ScanMode:                domain.ScanModeSidecar,
					SBOMCreatorVersion:      "syft-1.2.3",
					CVEScannerVersion:       "grype-4.5.6-matching-adaptive",
					CVEDBVersion:            "db-2026-08-11",
					ScanTimeout:             "5m0s",
					ScannerReadinessTimeout: "1m0s",
					StorageEnabled:          true,
					RiskAcceptanceEnabled:   true,
				}
			},
			expectedBody: `{"scanMode":"sidecar","sbomCreatorVersion":"syft-1.2.3","cveScannerVersion":"grype-4.5.6-matching-adaptive","cveDBVersion":"db-2026-08-11","scanTimeout":"5m0s","scannerReadinessTimeout":"1m0s","storageEnabled":true,"riskAcceptanceEnabled":true,"queueDepth":0}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pool := workerpool.New(1)
			t.Cleanup(pool.Stop)
			c := HTTPController{diagnostics: tt.diagnostics, workerPool: pool}
			router := gin.Default()
			path := "/v1/diagnostics"
			router.GET(path, c.Diagnostics)
			req, _ := http.NewRequest("GET", path, nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			assert.Equal(t, http.StatusOK, w.Code, w.Code)
			assert.JSONEq(t, tt.expectedBody, w.Body.String(), w.Body.String())
		})
	}
}

func TestHTTPController_Diagnostics_QueueDepth(t *testing.T) {
	pool := workerpool.New(1)
	release := make(chan struct{})
	t.Cleanup(func() {
		close(release)
		pool.StopWait()
	})

	pool.Submit(func() {
		<-release // occupy the pool's single worker
	})
	pool.Submit(func() {
		<-release // sits in the waiting queue behind the task above
	})

	// Give the pool a moment to actually dequeue the first task before asserting.
	require.Eventually(t, func() bool {
		return pool.WaitingQueueSize() > 0
	}, time.Second, time.Millisecond)

	c := HTTPController{workerPool: pool}
	router := gin.Default()
	router.GET("/v1/diagnostics", c.Diagnostics)
	req, _ := http.NewRequest("GET", "/v1/diagnostics", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	var got domain.Diagnostics
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))
	assert.Equal(t, 1, got.QueueDepth)
}

func TestHTTPController_ScanCVE(t *testing.T) {
	tests := []struct {
		name         string
		scanService  ports.ScanService
		expectedCode int
		expectedBody string
		yamlFile     string
	}{
		{
			name:         "invalid request",
			scanService:  services.NewMockScanService(true),
			expectedCode: http.StatusBadRequest,
			expectedBody: "{\"status\":400,\"title\":\"Bad Request\"}",
			yamlFile:     "../api/v1/testdata/scan-invalid.yaml",
		},
		{
			name:         "validation error",
			scanService:  services.NewMockScanService(false),
			expectedCode: http.StatusBadRequest,
			expectedBody: "{\"detail\":\"Wlid=wlid://cluster-minikube/namespace-kube-system/daemonset-kube-proxy, ImageHash=k8s.gcr.io/kube-proxy@sha256:c1b135231b5b1a6799346cd701da4b59e5b7ef8e694ec7b04fb23b8dbe144137\",\"status\":400,\"title\":\"Bad Request\"}",
			yamlFile:     "../api/v1/testdata/scan.yaml",
		},
		{
			name:         "ready",
			scanService:  services.NewMockScanService(true),
			expectedCode: http.StatusOK,
			expectedBody: "{\"detail\":\"Wlid=wlid://cluster-minikube/namespace-kube-system/daemonset-kube-proxy, ImageHash=k8s.gcr.io/kube-proxy@sha256:c1b135231b5b1a6799346cd701da4b59e5b7ef8e694ec7b04fb23b8dbe144137\",\"status\":200,\"title\":\"OK\"}",
			yamlFile:     "../api/v1/testdata/scan.yaml",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := HTTPController{
				scanService: tt.scanService,
				workerPool:  workerpool.New(1),
			}
			router := gin.Default()
			path := "/v1/scanImage"
			router.POST(path, c.ScanCVE)
			file, err := os.Open(tt.yamlFile)
			require.NoError(t, err)
			req, _ := http.NewRequest("POST", path, file)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			assert.Equal(t, tt.expectedCode, w.Code, w.Code)
			assert.Equal(t, tt.expectedBody, w.Body.String(), w.Body.String())
		})
	}
}

func TestHTTPController_ScanCP_MissingArgsDoesNotPanic(t *testing.T) {
	c := HTTPController{
		scanService: services.NewMockScanService(true),
		workerPool:  workerpool.New(1),
	}
	defer c.Shutdown(5 * time.Second)

	// gin.New() rather than gin.Default() so a regression that panics surfaces
	// as an unrecovered panic in this test instead of being masked by
	// gin.Recovery() into the same 400 the validation path returns.
	router := gin.New()
	router.POST("/v1/scanCP", c.ScanCP)

	req, _ := http.NewRequest("POST", "/v1/scanCP", strings.NewReader(`{
		"wlid": "wlid://cluster-x/namespace-y/deployment-z",
		"imageTag": "nginx:latest"
	}`))
	w := httptest.NewRecorder()

	assert.NotPanics(t, func() {
		router.ServeHTTP(w, req)
	})
}

// TestHTTPController_Shutdown_BoundedByTimeout is a regression test for #467: Shutdown
// used to delegate straight to workerPool.StopWait(), which blocks until every queued and
// currently-running task finishes with no deadline of its own. A single stuck task (e.g. a
// scan blocked on a backend call that ignores ctx cancellation, see #450) could therefore
// hang shutdown indefinitely, well past Kubernetes' terminationGracePeriodSeconds, ending in
// a silent SIGKILL instead of a bounded, logged abandonment.
func TestHTTPController_Shutdown_BoundedByTimeout(t *testing.T) {
	c := HTTPController{
		scanService: services.NewMockScanService(true),
		workerPool:  workerpool.New(1),
	}

	blocked := make(chan struct{})
	c.workerPool.Submit(func() {
		<-blocked
	})
	// Unblock the stuck task once the test is done so the pool's background dispatcher
	// goroutine (still draining in the background after Shutdown's timeout fires) can
	// actually finish instead of leaking for the rest of the test binary's lifetime.
	defer close(blocked)

	const timeout = 100 * time.Millisecond
	start := time.Now()
	c.Shutdown(timeout)
	elapsed := time.Since(start)

	assert.Less(t, elapsed, 2*time.Second,
		"Shutdown should return once its timeout elapses instead of blocking on a stuck task")
	assert.GreaterOrEqual(t, elapsed, timeout,
		"Shutdown should not return before its timeout when the pool hasn't drained yet")
}

// Before #758, nothing stopped a request handler from calling workerPool.Submit while (or
// after) Shutdown's workerPool.Stop() closed the pool's task channel -- a guaranteed "send
// on closed channel" panic. This proves submit() refuses work once shutdown has begun,
// instead of ever reaching the pool.
func TestHTTPController_Submit_RejectsAfterShutdown(t *testing.T) {
	h := &HTTPController{workerPool: workerpool.New(1)}
	h.Shutdown(time.Second)

	var ran atomic.Bool
	ok := h.submit(func() { ran.Store(true) })

	assert.False(t, ok, "submit must refuse work once shutdown has started")
	assert.False(t, ran.Load(), "a refused task must never run")
}

// This reproduces the actual race from #758 deterministically: a caller inside submit(),
// already past the shuttingDown check, races Shutdown starting concurrently. submitBeforeHook
// pins the caller in that exact window -- the one where the old code could still lose the
// race against workerPool.Stop() closing the task channel underneath it -- so releasing it
// is what lets Shutdown's submitGate.Lock() proceed at all; there is no sleep standing in
// for that guarantee. If submit() ever let this caller through only for workerPool.Submit to
// hand a closed channel, this test would crash with a "send on closed channel" panic instead
// of failing normally.
func TestHTTPController_SubmitRacingShutdown_DoesNotPanic(t *testing.T) {
	h := &HTTPController{workerPool: workerpool.New(1)}

	inHook := make(chan struct{})
	releaseHook := make(chan struct{})
	h.submitBeforeHook = func() {
		close(inHook)
		<-releaseHook
	}

	var ran atomic.Bool
	submitOK := make(chan bool, 1)
	go func() {
		submitOK <- h.submit(func() { ran.Store(true) })
	}()

	<-inHook // submit() is now paused holding submitGate for read.

	shutdownDone := make(chan struct{})
	go func() {
		h.Shutdown(2 * time.Second)
		close(shutdownDone)
	}()

	close(releaseHook)

	require.True(t, <-submitOK, "a submit() call already past the shutdown check must still succeed")
	select {
	case <-shutdownDone:
	case <-time.After(time.Second):
		t.Fatal("shutdown did not finish in time")
	}
	assert.True(t, ran.Load(), "the task submitted just before shutdown must still run")
}

// When submit() loses the race and refuses a job that was already accepted (its 200 OK
// response already written -- see submit's doc comment), runTrackedScan must release the
// admission slot itself, since the submitted closure that would normally do that via its
// own deferred release() never got created, and must mark the job abandoned instead of
// leaving it stuck "accepted" forever.
func TestHTTPController_RunTrackedScan_AbandonsJobWhenShuttingDown(t *testing.T) {
	h := (&HTTPController{workerPool: workerpool.New(1)}).WithMaxQueueDepth(1)
	require.True(t, h.tryAdmit())
	h.ensureStatuses().recordAccepted("job-1", "generateSBOM")
	h.shuttingDown = true // simulate having lost the race, without a real Shutdown call

	var scanCalled atomic.Bool
	h.runTrackedScan(context.Background(), "job-1", "generateSBOM",
		func(context.Context) error { scanCalled.Store(true); return nil }, "unused")

	assert.False(t, scanCalled.Load(), "a job abandoned to shutdown must never actually run")
	assert.EqualValues(t, 0, h.pending.Load(), "the admission slot must be released")

	status, ok := h.ensureStatuses().get("job-1")
	require.True(t, ok)
	assert.Equal(t, domain.ScanStateAbandoned, status.State)
	assert.Equal(t, domain.ScanReasonShutdownAbandoned, status.Reason)
	assert.Equal(t, string(domain.ScanStateAbandoned), status.Phase,
		"markAbandoned must report the same Phase convention as markAbandonedQueued, not the generic \"completed\" every other terminal state gets")
}

func TestHTTPController_ScanRegistry(t *testing.T) {
	tests := []struct {
		name         string
		scanService  ports.ScanService
		expectedCode int
		expectedBody string
		yamlFile     string
	}{
		{
			name:         "invalid request",
			scanService:  services.NewMockScanService(true),
			expectedCode: http.StatusBadRequest,
			expectedBody: "{\"status\":400,\"title\":\"Bad Request\"}",
			yamlFile:     "../api/v1/testdata/scan-invalid.yaml",
		},
		{
			name:         "validation error",
			scanService:  services.NewMockScanService(false),
			expectedCode: http.StatusBadRequest,
			expectedBody: "{\"detail\":\"ImageTag=k8s.gcr.io/kube-proxy:v1.24.3\",\"status\":400,\"title\":\"Bad Request\"}",
			yamlFile:     "../api/v1/testdata/scan.yaml",
		},
		{
			name:         "ready",
			scanService:  services.NewMockScanService(true),
			expectedCode: http.StatusOK,
			expectedBody: "{\"detail\":\"ImageTag=k8s.gcr.io/kube-proxy:v1.24.3\",\"status\":200,\"title\":\"OK\"}",
			yamlFile:     "../api/v1/testdata/scan.yaml",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := HTTPController{
				scanService: tt.scanService,
				workerPool:  workerpool.New(1),
			}
			router := gin.Default()
			path := "/v1/scanRegistryImage"
			router.POST(path, c.ScanRegistry)
			file, err := os.Open(tt.yamlFile)
			require.NoError(t, err)
			req, _ := http.NewRequest("POST", path, file)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			assert.Equal(t, tt.expectedCode, w.Code, w.Code)
			assert.Equal(t, tt.expectedBody, w.Body.String(), w.Body.String())
		})
	}
}

func Test_registryScanCommandToScanCommand(t *testing.T) {

	tests := []struct {
		wssc.RegistryScanCommand
	}{
		{
			wssc.RegistryScanCommand{
				ImageScanParams: wssc.ImageScanParams{
					Credentialslist: []registry.AuthConfig{},
					ImageTag:        "docker.io/library/nginx:1.14.1",
					JobID:           "some Job ID for nginx",
					ParentJobID:     "some Parent Job ID for nginx",
				},
			},
		},
		{
			wssc.RegistryScanCommand{
				ImageScanParams: wssc.ImageScanParams{
					Credentialslist: []registry.AuthConfig{},
					ImageTag:        "nginx@sha256:73e957703f1266530db0aeac1fd6a3f87c1e59943f4c13eb340bb8521c6041d7",
					JobID:           "some Job ID for nginx sha",
					ParentJobID:     "some Parent Job ID for nginx sha",
				},
			},
		},
		{
			wssc.RegistryScanCommand{
				ImageScanParams: wssc.ImageScanParams{
					Credentialslist: []registry.AuthConfig{},
					ImageTag:        "nginx:latest",
					JobID:           "some Job ID for nginx latest",
					ParentJobID:     "some Parent Job ID for nginx latest",
				},
			},
		},
		{
			wssc.RegistryScanCommand{
				ImageScanParams: wssc.ImageScanParams{
					Credentialslist: []registry.AuthConfig{},
					ImageTag:        "docker.io/library/nginx:latest",
					JobID:           "some Job ID for nginx latest with docker hub",
					ParentJobID:     "some Parent Job ID for nginx latest with docker hub",
				},
			},
		},
		{
			wssc.RegistryScanCommand{
				ImageScanParams: wssc.ImageScanParams{
					Credentialslist: []registry.AuthConfig{},
					ImageTag:        "docker.io/library/nginx:latest@sha256:73e957703f1266530db0aeac1fd6a3f87c1e59943f4c13eb340bb8521c6041d7",
					JobID:           "some Job ID for nginx latest with docker hub library",
					ParentJobID:     "some Parent Job ID for nginx latest with docker hub library",
				},
			},
		},
	}
	for i := range tests {
		scanComm := registryScanCommandToScanCommand(tests[i].RegistryScanCommand)
		assert.Equal(t, tests[i].Credentialslist, scanComm.CredentialsList)
		assert.Equal(t, tests[i].ImageTag, scanComm.ImageTag)
		assert.Equal(t, tools.NormalizeReference(tests[i].ImageTag), scanComm.ImageTagNormalized)
		assert.Equal(t, v1.NormalizeImageID("", tests[i].ImageTag), scanComm.ImageHash)
		expectedSlug, err := names.ImageInfoToSlug(tools.NormalizeReference(tests[i].ImageTag), "nohash")
		require.NoError(t, err)
		assert.Equal(t, expectedSlug, scanComm.ImageSlug)
		assert.Equal(t, tests[i].JobID, scanComm.JobID)
		assert.Equal(t, tests[i].ParentJobID, scanComm.ParentJobID)
	}
}

type contextSpyScanService struct {
	lastGenerateSBOMCtx context.Context
	lastScanCPCtx       context.Context
	lastScanCVECtx      context.Context
	lastScanRegistryCtx context.Context
	generateSBOMCh      chan struct{}
	scanCPCh            chan struct{}
	scanCVECh           chan struct{}
	scanRegistryCh      chan struct{}
}

var _ ports.ScanService = (*contextSpyScanService)(nil)

func (s *contextSpyScanService) GenerateSBOM(ctx context.Context) error {
	s.lastGenerateSBOMCtx = ctx
	close(s.generateSBOMCh)
	return nil
}

func (s *contextSpyScanService) Ready(ctx context.Context) bool {
	return true
}

func (s *contextSpyScanService) ScanCP(ctx context.Context) error {
	s.lastScanCPCtx = ctx
	close(s.scanCPCh)
	return nil
}

func (s *contextSpyScanService) ScanCVE(ctx context.Context) error {
	s.lastScanCVECtx = ctx
	close(s.scanCVECh)
	return nil
}

func (s *contextSpyScanService) ScanRegistry(ctx context.Context) error {
	s.lastScanRegistryCtx = ctx
	close(s.scanRegistryCh)
	return nil
}

func (s *contextSpyScanService) ValidateGenerateSBOM(ctx context.Context, _ domain.ScanCommand) (context.Context, error) {
	return ctx, nil
}

func (s *contextSpyScanService) ValidateScanCP(ctx context.Context, _ domain.ScanCommand) (context.Context, error) {
	return ctx, nil
}

func (s *contextSpyScanService) ValidateScanCVE(ctx context.Context, _ domain.ScanCommand) (context.Context, error) {
	return ctx, nil
}

func (s *contextSpyScanService) ValidateScanRegistry(ctx context.Context, _ domain.ScanCommand) (context.Context, error) {
	return ctx, nil
}

func TestHTTPController_ContextCancellationIsDetached(t *testing.T) {
	spy := &contextSpyScanService{
		generateSBOMCh: make(chan struct{}),
		scanCPCh:       make(chan struct{}),
		scanCVECh:      make(chan struct{}),
		scanRegistryCh: make(chan struct{}),
	}

	c := HTTPController{
		scanService: spy,
		workerPool:  workerpool.New(4),
	}
	defer c.Shutdown(5 * time.Second)

	router := gin.Default()
	router.POST("/v1/generateSBOM", c.GenerateSBOM)
	router.POST("/v1/scanCP", c.ScanCP)
	router.POST("/v1/scanCVE", c.ScanCVE)
	router.POST("/v1/scanRegistryImage", c.ScanRegistry)

	// Helper function to send requests
	sendRequest := func(path string) {
		payload := `{
			"imageTag": "k8s.gcr.io/kube-proxy:v1.24.3",
			"wlid": "wlid://cluster-minikube/namespace-kube-system/daemonset-kube-proxy",
			"containerName": "kube-proxy",
			"imageHash": "k8s.gcr.io/kube-proxy@sha256:c1b135231b5b1a6799346cd701da4b59e5b7ef8e694ec7b04fb23b8dbe144137",
			"args": {
				"name": "daemonset-kube-proxy",
				"namespace": "kube-system"
			}
		}`
		req, _ := http.NewRequest("POST", path, strings.NewReader(payload))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	}

	// 1. GenerateSBOM
	sendRequest("/v1/generateSBOM")
	select {
	case <-spy.generateSBOMCh:
		assert.NoError(t, spy.lastGenerateSBOMCtx.Err())
	case <-time.After(1 * time.Second):
		t.Fatal("GenerateSBOM worker was not executed in time")
	}

	// 2. ScanCP
	sendRequest("/v1/scanCP")
	select {
	case <-spy.scanCPCh:
		assert.NoError(t, spy.lastScanCPCtx.Err())
	case <-time.After(1 * time.Second):
		t.Fatal("ScanCP worker was not executed in time")
	}

	// 3. ScanCVE
	sendRequest("/v1/scanCVE")
	select {
	case <-spy.scanCVECh:
		assert.NoError(t, spy.lastScanCVECtx.Err())
	case <-time.After(1 * time.Second):
		t.Fatal("ScanCVE worker was not executed in time")
	}

	// 4. ScanRegistry
	sendRequest("/v1/scanRegistryImage")
	select {
	case <-spy.scanRegistryCh:
		assert.NoError(t, spy.lastScanRegistryCtx.Err())
	case <-time.After(1 * time.Second):
		t.Fatal("ScanRegistry worker was not executed in time")
	}
}

func TestHTTPController_GenerateSBOM_EmptyJobIDStillRuns(t *testing.T) {
	spy := &contextSpyScanService{
		generateSBOMCh: make(chan struct{}),
	}

	c := HTTPController{
		scanService: spy,
		workerPool:  workerpool.New(1),
	}
	defer c.Shutdown(5 * time.Second)

	router := gin.Default()
	router.POST("/v1/generateSBOM", c.GenerateSBOM)

	req, _ := http.NewRequest("POST", "/v1/generateSBOM", strings.NewReader(`{
		"imageTag": "k8s.gcr.io/kube-proxy:v1.24.3",
		"imageHash": "k8s.gcr.io/kube-proxy@sha256:c1b135231b5b1a6799346cd701da4b59e5b7ef8e694ec7b04fb23b8dbe144137"
	}`))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	select {
	case <-spy.generateSBOMCh:
		assert.NoError(t, spy.lastGenerateSBOMCtx.Err())
	case <-time.After(1 * time.Second):
		t.Fatal("GenerateSBOM worker was not executed in time")
	}
}

func TestValidationStatusCode(t *testing.T) {
	assert.Equal(t, http.StatusTooManyRequests, validationStatusCode(domain.ErrTooManyRequests))
	assert.Equal(t, http.StatusServiceUnavailable, validationStatusCode(domain.ErrQueueFull))
	assert.Equal(t, http.StatusBadRequest, validationStatusCode(domain.ErrMissingCpInfo))
	assert.Equal(t, http.StatusBadRequest, validationStatusCode(domain.ErrMockError))
}

// validateErrScanService returns a fixed error from every Validate* method so
// handler tests can exercise a specific validation error without depending on
// MockScanService's generic sad path.
type validateErrScanService struct {
	*services.MockScanService
	err error
}

func (s validateErrScanService) ValidateGenerateSBOM(ctx context.Context, _ domain.ScanCommand) (context.Context, error) {
	return ctx, s.err
}

func (s validateErrScanService) ValidateScanCVE(ctx context.Context, _ domain.ScanCommand) (context.Context, error) {
	return ctx, s.err
}

func (s validateErrScanService) ValidateScanRegistry(ctx context.Context, _ domain.ScanCommand) (context.Context, error) {
	return ctx, s.err
}

func TestHTTPController_GenerateSBOM_TooManyRequests(t *testing.T) {
	c := HTTPController{
		scanService: validateErrScanService{MockScanService: services.NewMockScanService(true), err: domain.ErrTooManyRequests},
		workerPool:  workerpool.New(1),
	}
	router := gin.Default()
	router.POST("/v1/generateSBOM", c.GenerateSBOM)
	file, err := os.Open("../api/v1/testdata/scan.yaml")
	require.NoError(t, err)
	req, _ := http.NewRequest("POST", "/v1/generateSBOM", file)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusTooManyRequests, w.Code, w.Body.String())
}

func TestHTTPController_MetricsEndpoint(t *testing.T) {
	startedC := make(chan struct{}, 1)
	c := NewHTTPController(scanErrorService{
		MockScanService: services.NewMockScanService(true),
		startedC:        startedC,
	}, 1)
	m, err := metrics.New()
	require.NoError(t, err)
	_, err = c.WithMetrics(m)
	require.NoError(t, err)

	router := gin.Default()
	router.POST("/v1/generateSBOM", c.GenerateSBOM)
	router.GET("/metrics", gin.WrapH(m.Handler()))

	file, err := os.Open("../api/v1/testdata/scan.yaml")
	require.NoError(t, err)
	req, _ := http.NewRequest("POST", "/v1/generateSBOM", file)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	select {
	case <-startedC:
	case <-time.After(1 * time.Second):
		t.Fatal("scan worker was not executed in time")
	}

	c.Shutdown(5 * time.Second)

	req, _ = http.NewRequest("GET", "/metrics", nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()
	assert.True(t, strings.Contains(body, "kubevuln_scans_completed_total"), body)
	assert.True(t, strings.Contains(body, "kubevuln_scan_duration_seconds"), body)
	assert.True(t, strings.Contains(body, "kubevuln_worker_pool_queue_depth"), body)
}

func TestHTTPController_MetricsEndpoint_RecordsRejection(t *testing.T) {
	c := &HTTPController{
		scanService: validateErrScanService{MockScanService: services.NewMockScanService(true), err: domain.ErrTooManyRequests},
		workerPool:  workerpool.New(1),
	}
	m, err := metrics.New()
	require.NoError(t, err)
	c, err = c.WithMetrics(m)
	require.NoError(t, err)

	router := gin.Default()
	router.POST("/v1/generateSBOM", c.GenerateSBOM)
	router.GET("/metrics", gin.WrapH(m.Handler()))

	file, err := os.Open("../api/v1/testdata/scan.yaml")
	require.NoError(t, err)
	req, _ := http.NewRequest("POST", "/v1/generateSBOM", file)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	require.Equal(t, http.StatusTooManyRequests, w.Code, w.Body.String())

	req, _ = http.NewRequest("GET", "/metrics", nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()
	assert.True(t, strings.Contains(body, `reason="too_many_requests"`), body)
	assert.True(t, strings.Contains(body, `kubevuln_scan_rejections_total{endpoint="generateSBOM",reason="too_many_requests"} 1`), body)
	assert.False(t, strings.Contains(body, `reason="invalid_request"`), body)
}

func TestHTTPController_MetricsEndpoint_ExportsScanFallbackMetrics(t *testing.T) {
	c := NewHTTPController(services.NewMockScanService(true), 1)
	t.Cleanup(func() {
		c.Shutdown(5 * time.Second)
	})
	m, err := metrics.New()
	require.NoError(t, err)
	_, err = c.WithMetrics(m)
	require.NoError(t, err)

	router := gin.Default()
	router.GET("/metrics", gin.WrapH(m.Handler()))

	metrics.RecordScanFallback(context.Background(), metrics.ComponentSidecar, metrics.FallbackCategoryRegistryAuth, metrics.FallbackStrategyGCPADC, metrics.FallbackOutcomeFailed)
	metrics.RecordScanFallback(context.Background(), metrics.ComponentSidecar, metrics.FallbackCategoryPlatform, metrics.FallbackStrategyPlatformMismatch, metrics.FallbackOutcomeFailed)
	metrics.RecordScanFallback(context.Background(), metrics.ComponentSidecar, metrics.FallbackCategorySizeClassification, metrics.FallbackStrategySBOMTooLarge, metrics.FallbackOutcomeClassified)
	metrics.RecordSourceResolution(context.Background(), metrics.ComponentSidecar, true, false)

	req, _ := http.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()
	assert.True(t, strings.Contains(body, `kubevuln_scan_fallbacks_total{category="registry_auth",component="sidecar",outcome="failed",strategy="gcp_adc"} 1`), body)
	assert.True(t, strings.Contains(body, `kubevuln_scan_fallbacks_total{category="platform",component="sidecar",outcome="failed",strategy="platform_mismatch"} 1`), body)
	assert.True(t, strings.Contains(body, `kubevuln_scan_fallbacks_total{category="size_classification",component="sidecar",outcome="classified",strategy="sbom_too_large"} 1`), body)
	assert.True(t, strings.Contains(body, `kubevuln_scan_source_resolution_total{component="sidecar",outcome="fallback_failed"} 1`), body)
}

// TestHTTPController_MetricsEndpoint_InvalidRequestDoesNotCountAsRejection is a
// regression test: a malformed-payload validation error (not ErrTooManyRequests)
// must be recorded under reason="invalid_request", and must NOT be conflated with
// the too_many_requests series that rate-limit alerts key off of.
func TestHTTPController_MetricsEndpoint_InvalidRequestDoesNotCountAsRejection(t *testing.T) {
	c := &HTTPController{
		scanService: validateErrScanService{MockScanService: services.NewMockScanService(true), err: domain.ErrMissingImageInfo},
		workerPool:  workerpool.New(1),
	}
	m, err := metrics.New()
	require.NoError(t, err)
	c, err = c.WithMetrics(m)
	require.NoError(t, err)

	router := gin.Default()
	router.POST("/v1/generateSBOM", c.GenerateSBOM)
	router.GET("/metrics", gin.WrapH(m.Handler()))

	file, err := os.Open("../api/v1/testdata/scan.yaml")
	require.NoError(t, err)
	req, _ := http.NewRequest("POST", "/v1/generateSBOM", file)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	require.NotEqual(t, http.StatusTooManyRequests, w.Code, w.Body.String())

	req, _ = http.NewRequest("GET", "/metrics", nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()
	assert.True(t, strings.Contains(body, `kubevuln_scan_rejections_total{endpoint="generateSBOM",reason="invalid_request"} 1`), body)
	assert.False(t, strings.Contains(body, `reason="too_many_requests"`), body)
}

// scanErrorService validates every request successfully, then returns a fixed error from
// whichever scan flow the test exercises -- used to prove HTTPController.recordScan resolves
// a specific reason label (see scanFailureReason) all the way from the scan service's error,
// through the worker pool, onto the kubevuln_scans_completed_total/kubevuln_scan_duration_seconds
// metrics (see #540).
type scanErrorService struct {
	*services.MockScanService
	err      error
	startedC chan<- struct{}
}

func (s scanErrorService) signalStarted() {
	if s.startedC == nil {
		return
	}
	select {
	case s.startedC <- struct{}{}:
	default:
	}
}

func (s scanErrorService) GenerateSBOM(context.Context) error {
	s.signalStarted()
	return s.err
}

func (s scanErrorService) ScanCVE(context.Context) error {
	s.signalStarted()
	return s.err
}

func (s scanErrorService) ScanRegistry(context.Context) error {
	s.signalStarted()
	return s.err
}

func (s scanErrorService) ScanCP(context.Context) error {
	s.signalStarted()
	return s.err
}

func (s scanErrorService) ValidateGenerateSBOM(ctx context.Context, _ domain.ScanCommand) (context.Context, error) {
	return ctx, nil
}

func (s scanErrorService) ValidateScanCVE(ctx context.Context, _ domain.ScanCommand) (context.Context, error) {
	return ctx, nil
}

func (s scanErrorService) ValidateScanRegistry(ctx context.Context, _ domain.ScanCommand) (context.Context, error) {
	return ctx, nil
}

// TestHTTPController_MetricsEndpoint_RecordsScanFailureReason is a regression test for #540:
// every scan flow used to collapse its failure into a bare outcome="error" label, discarding
// the scanfailure.Reason* classification already computed in core/services/scan.go. It now
// rides along on a *domain.ScanError and lands on the "reason" attribute of both
// kubevuln_scans_completed_total and kubevuln_scan_duration_seconds, one specific value per
// endpoint instead of a single opaque bucket.
func TestHTTPController_MetricsEndpoint_RecordsScanFailureReason(t *testing.T) {
	tests := []struct {
		name         string
		path         string
		endpoint     string
		register     func(router *gin.Engine, c *HTTPController)
		wantReason   string
		unclassified bool // when true, err is a bare error instead of *domain.ScanError
	}{
		{
			name:       "generateSBOM, classified reason",
			path:       "/v1/generateSBOM",
			endpoint:   "generateSBOM",
			register:   func(router *gin.Engine, c *HTTPController) { router.POST("/v1/generateSBOM", c.GenerateSBOM) },
			wantReason: scanfailure.ReasonSBOMIncomplete,
		},
		{
			name:       "scanCVE, classified reason",
			path:       "/v1/scanImage",
			endpoint:   "scanCVE",
			register:   func(router *gin.Engine, c *HTTPController) { router.POST("/v1/scanImage", c.ScanCVE) },
			wantReason: scanfailure.ReasonCVEMatchingFailed,
		},
		{
			name:       "scanRegistryImage, classified reason",
			path:       "/v1/scanRegistryImage",
			endpoint:   "scanRegistry",
			register:   func(router *gin.Engine, c *HTTPController) { router.POST("/v1/scanRegistryImage", c.ScanRegistry) },
			wantReason: scanfailure.ReasonImageAuthFailed,
		},
		{
			name:         "generateSBOM, unclassified error defaults to unexpected",
			path:         "/v1/generateSBOM",
			endpoint:     "generateSBOM",
			register:     func(router *gin.Engine, c *HTTPController) { router.POST("/v1/generateSBOM", c.GenerateSBOM) },
			wantReason:   scanfailure.ReasonUnexpected,
			unclassified: true,
		},
		{
			// regression test for #816: a real per-container failure inside ScanCP must
			// surface as outcome="error" with a classified reason, not "success".
			name:       "scanCP, classified reason",
			path:       "/v1/scanCP",
			endpoint:   "scanCP",
			register:   func(router *gin.Engine, c *HTTPController) { router.POST("/v1/scanCP", c.ScanCP) },
			wantReason: scanfailure.ReasonCVEMatchingFailed,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var scanErr error = &domain.ScanError{Reason: tt.wantReason, Err: errors.New("boom")}
			if tt.unclassified {
				scanErr = errors.New("boom")
			}
			startedC := make(chan struct{}, 1)
			c := &HTTPController{
				scanService: scanErrorService{
					MockScanService: services.NewMockScanService(true),
					err:             scanErr,
					startedC:        startedC,
				},
				workerPool: workerpool.New(1),
			}
			m, err := metrics.New()
			require.NoError(t, err)
			c, err = c.WithMetrics(m)
			require.NoError(t, err)

			router := gin.Default()
			tt.register(router, c)
			router.GET("/metrics", gin.WrapH(m.Handler()))

			file, err := os.Open("../api/v1/testdata/scan.yaml")
			require.NoError(t, err)
			req, _ := http.NewRequest("POST", tt.path, file)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			require.Equal(t, http.StatusOK, w.Code, w.Body.String())
			select {
			case <-startedC:
			case <-time.After(1 * time.Second):
				t.Fatal("scan worker was not executed in time")
			}

			c.Shutdown(5 * time.Second)

			req, _ = http.NewRequest("GET", "/metrics", nil)
			w = httptest.NewRecorder()
			router.ServeHTTP(w, req)
			require.Equal(t, http.StatusOK, w.Code)

			body := w.Body.String()
			wantSeries := `kubevuln_scans_completed_total{endpoint="` + tt.endpoint + `",outcome="error",reason="` + tt.wantReason + `"} 1`
			assert.True(t, strings.Contains(body, wantSeries), body)
			wantDurationSeries := `kubevuln_scan_duration_seconds_count{endpoint="` + tt.endpoint + `",outcome="error",reason="` + tt.wantReason + `"} 1`
			assert.True(t, strings.Contains(body, wantDurationSeries), body)
		})
	}
}

type statusFlowScanService struct {
	*services.MockScanService
	err       error
	blockCh   <-chan struct{}
	startedCh chan<- struct{}
	phase     string
}

func (s statusFlowScanService) GenerateSBOM(ctx context.Context) error {
	if s.phase != "" {
		domain.UpdateScanPhase(ctx, s.phase)
	}
	if s.startedCh != nil {
		select {
		case s.startedCh <- struct{}{}:
		default:
		}
	}
	if s.blockCh != nil {
		<-s.blockCh
	}
	return s.err
}

func (s statusFlowScanService) ValidateGenerateSBOM(ctx context.Context, _ domain.ScanCommand) (context.Context, error) {
	return ctx, nil
}

func (s statusFlowScanService) ScanCP(ctx context.Context) error {
	if s.phase != "" {
		domain.UpdateScanPhase(ctx, s.phase)
	}
	if s.startedCh != nil {
		select {
		case s.startedCh <- struct{}{}:
		default:
		}
	}
	if s.blockCh != nil {
		<-s.blockCh
	}
	return s.err
}

func TestHTTPController_ScanStatus_Succeeded(t *testing.T) {
	c := NewHTTPController(statusFlowScanService{
		MockScanService: services.NewMockScanService(true),
		phase:           "result_upload",
	}, 1)
	t.Cleanup(func() { c.Shutdown(5 * time.Second) })

	router := gin.Default()
	router.POST("/v1/generateSBOM", c.GenerateSBOM)
	router.GET("/v1/scanStatus/:jobID", c.ScanStatus)

	req, _ := http.NewRequest("POST", "/v1/generateSBOM", strings.NewReader(`{"imageTag":"nginx:1.24","imageHash":"sha256:1","jobID":"job-success"}`))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	var status domain.ScanStatus
	require.Eventually(t, func() bool {
		req, _ = http.NewRequest("GET", "/v1/scanStatus/job-success", nil)
		w = httptest.NewRecorder()
		router.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			return false
		}
		if err := json.Unmarshal(w.Body.Bytes(), &status); err != nil {
			return false
		}
		return status.State == domain.ScanStateSucceeded
	}, time.Second, 10*time.Millisecond)

	assert.Equal(t, "generateSBOM", status.Endpoint)
	assert.Equal(t, "completed", status.Phase)
	require.NotNil(t, status.StartedAt)
	require.NotNil(t, status.FinishedAt)
	assert.True(t, status.AcceptedAt.Before(*status.FinishedAt) || status.AcceptedAt.Equal(*status.FinishedAt))
	assert.False(t, status.StartedAt.IsZero())
	assert.False(t, status.FinishedAt.IsZero())
	assert.Empty(t, status.Reason)
}

func TestHTTPController_ScanStatus_Failed(t *testing.T) {
	c := NewHTTPController(statusFlowScanService{
		MockScanService: services.NewMockScanService(true),
		err:             &domain.ScanError{Reason: scanfailure.ReasonCVEMatchingFailed, Err: errors.New("boom")},
	}, 1)
	t.Cleanup(func() { c.Shutdown(5 * time.Second) })

	router := gin.Default()
	router.POST("/v1/generateSBOM", c.GenerateSBOM)
	router.GET("/v1/scanStatus/:jobID", c.ScanStatus)

	req, _ := http.NewRequest("POST", "/v1/generateSBOM", strings.NewReader(`{"imageTag":"nginx:1.24","imageHash":"sha256:2","jobID":"job-failed"}`))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	var status domain.ScanStatus
	require.Eventually(t, func() bool {
		req, _ = http.NewRequest("GET", "/v1/scanStatus/job-failed", nil)
		w = httptest.NewRecorder()
		router.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			return false
		}
		if err := json.Unmarshal(w.Body.Bytes(), &status); err != nil {
			return false
		}
		return status.State == domain.ScanStateFailed
	}, time.Second, 10*time.Millisecond)

	assert.Equal(t, scanfailure.ReasonCVEMatchingFailed, status.Reason)
	assert.Equal(t, "completed", status.Phase)
	require.NotNil(t, status.FinishedAt)
	assert.False(t, status.FinishedAt.IsZero())
}

// TestHTTPController_ScanStatus_ScanCPFailed is a regression test for #816: ScanCP's own
// closure (it does not go through runTrackedScan, see that function's doc comment) used to
// mark the job succeeded no matter what its per-container loop actually did. A failure
// returned from the scan service must now reach /v1/scanStatus as state="failed" with its
// classified reason, exactly like GenerateSBOM/ScanCVE/ScanRegistry already do.
func TestHTTPController_ScanStatus_ScanCPFailed(t *testing.T) {
	c := NewHTTPController(statusFlowScanService{
		MockScanService: services.NewMockScanService(true),
		err:             &domain.ScanError{Reason: scanfailure.ReasonCVEMatchingFailed, Err: errors.New("boom")},
	}, 1)
	t.Cleanup(func() { c.Shutdown(5 * time.Second) })

	router := gin.Default()
	router.POST("/v1/scanCP", c.ScanCP)
	router.GET("/v1/scanStatus/:jobID", c.ScanStatus)

	req, _ := http.NewRequest("POST", "/v1/scanCP", strings.NewReader(`{
		"jobID": "job-scancp-failed",
		"args": {"name": "daemonset-kube-proxy", "namespace": "kube-system"}
	}`))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	var status domain.ScanStatus
	require.Eventually(t, func() bool {
		req, _ = http.NewRequest("GET", "/v1/scanStatus/job-scancp-failed", nil)
		w = httptest.NewRecorder()
		router.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			return false
		}
		if err := json.Unmarshal(w.Body.Bytes(), &status); err != nil {
			return false
		}
		return status.State == domain.ScanStateFailed
	}, time.Second, 10*time.Millisecond)

	assert.Equal(t, scanfailure.ReasonCVEMatchingFailed, status.Reason)
	require.NotNil(t, status.FinishedAt)
	assert.False(t, status.FinishedAt.IsZero())
}

func TestHTTPController_ScanStatus_AbandonedOnShutdown(t *testing.T) {
	blocked := make(chan struct{})
	started := make(chan struct{}, 1)
	release := func() {
		select {
		case <-blocked:
		default:
			close(blocked)
		}
	}
	c := NewHTTPController(statusFlowScanService{
		MockScanService: services.NewMockScanService(true),
		blockCh:         blocked,
		startedCh:       started,
	}, 1)
	t.Cleanup(release)

	router := gin.Default()
	router.POST("/v1/generateSBOM", c.GenerateSBOM)
	router.GET("/v1/scanStatus/:jobID", c.ScanStatus)

	firstReq, _ := http.NewRequest("POST", "/v1/generateSBOM", strings.NewReader(`{"imageTag":"nginx:1.24","imageHash":"sha256:3","jobID":"job-running"}`))
	firstW := httptest.NewRecorder()
	router.ServeHTTP(firstW, firstReq)
	require.Equal(t, http.StatusOK, firstW.Code, firstW.Body.String())

	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("first job did not start in time")
	}

	secondReq, _ := http.NewRequest("POST", "/v1/generateSBOM", strings.NewReader(`{"imageTag":"nginx:1.24","imageHash":"sha256:4","jobID":"job-abandoned"}`))
	secondW := httptest.NewRecorder()
	router.ServeHTTP(secondW, secondReq)
	require.Equal(t, http.StatusOK, secondW.Code, secondW.Body.String())

	done := make(chan struct{})
	go func() {
		c.Shutdown(20 * time.Millisecond)
		close(done)
	}()

	var status domain.ScanStatus
	require.Eventually(t, func() bool {
		req, _ := http.NewRequest("GET", "/v1/scanStatus/job-abandoned", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			return false
		}
		if err := json.Unmarshal(w.Body.Bytes(), &status); err != nil {
			return false
		}
		return status.State == domain.ScanStateAbandoned
	}, time.Second, 10*time.Millisecond)

	assert.Equal(t, domain.ScanReasonShutdownAbandoned, status.Reason)
	assert.Equal(t, string(domain.ScanStateAbandoned), status.Phase)
	require.NotNil(t, status.FinishedAt)
	assert.False(t, status.FinishedAt.IsZero())

	release()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("shutdown did not finish in time")
	}
}

// HTTPController carries a sync.Once, so a method on the value type copies that Once along
// with the rest of the struct. Nothing goes wrong while none of them reach ensureStatuses,
// but the copy's Once starts unfired, so one that did would build a second status store and
// write into an object no request ever reads. go vet reports this as copylocks; the repo's
// lint runs against the diff rather than the whole tree, so four of these sat on main
// unnoticed from the commit that added the Once.
//
// reflect lists only exported methods, which is where the risk is: those are the gin handlers.
func TestHTTPController_NoValueReceiverMethods(t *testing.T) {
	valueType := reflect.TypeOf(HTTPController{})
	var offenders []string
	for i := 0; i < valueType.NumMethod(); i++ {
		offenders = append(offenders, valueType.Method(i).Name)
	}
	assert.Empty(t, offenders, "these take a value receiver and so copy the sync.Once: %v", offenders)
}

// TestHTTPController_TryAdmitRelease exercises tryAdmit/release directly (regression
// coverage for #748: workerpool.Submit never blocks and its queue is otherwise unbounded, so
// this pair is the only thing standing between a request burst and unbounded memory growth).
func TestHTTPController_TryAdmitRelease(t *testing.T) {
	t.Run("unbounded by default", func(t *testing.T) {
		h := &HTTPController{}
		for range 1000 {
			require.True(t, h.tryAdmit())
		}
		// release is a no-op when unbounded: it must not panic or drive pending negative.
		h.release()
		assert.EqualValues(t, 0, h.pending.Load())
	})

	t.Run("bounded rejects at capacity and admits again after release", func(t *testing.T) {
		h := (&HTTPController{}).WithMaxQueueDepth(2)

		require.True(t, h.tryAdmit())
		require.True(t, h.tryAdmit())
		assert.False(t, h.tryAdmit(), "a third admission must be rejected once at capacity")
		assert.EqualValues(t, 2, h.pending.Load())

		h.release()
		assert.EqualValues(t, 1, h.pending.Load())
		assert.True(t, h.tryAdmit(), "a slot freed by release must be admittable again")
		assert.EqualValues(t, 2, h.pending.Load())
	})

	t.Run("non-positive depth means unbounded", func(t *testing.T) {
		for _, depth := range []int{0, -1} {
			h := (&HTTPController{}).WithMaxQueueDepth(depth)
			for range 100 {
				require.True(t, h.tryAdmit(), "depth=%d", depth)
			}
		}
	})

	// A depth above math.MaxInt32 must not be admittable at all: an int32-narrowed limit
	// wraps negative, so an unguarded comparison would make every admission attempt read
	// pending (0) as already past the limit and reject unconditionally, on a 64-bit build
	// where int is 64 bits.
	t.Run("depth above math.MaxInt32 does not wrap and still admits", func(t *testing.T) {
		h := (&HTTPController{}).WithMaxQueueDepth(math.MaxInt32 + 1)
		require.True(t, h.tryAdmit(), "a depth above math.MaxInt32 must still admit, not wrap negative and reject everything")
		assert.EqualValues(t, 1, h.pending.Load())
	})
}

// TestHTTPController_TryAdmitNoOvershootUnderConcurrency proves the CAS loop in tryAdmit
// admits exactly maxQueueDepth callers when many race it at once, not more (an unguarded
// check-then-act against pending could overshoot) and not fewer (a buggy CAS could starve a
// caller that should have been admitted).
func TestHTTPController_TryAdmitNoOvershootUnderConcurrency(t *testing.T) {
	const depth = 10
	const racers = 200

	h := (&HTTPController{}).WithMaxQueueDepth(depth)

	var admitted atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	wg.Add(racers)
	for range racers {
		go func() {
			defer wg.Done()
			<-start
			if h.tryAdmit() {
				admitted.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()

	assert.EqualValues(t, depth, admitted.Load())
	assert.EqualValues(t, depth, h.pending.Load())
}

// TestHTTPController_GenerateSBOM_QueueFull is the HTTP-level regression test for #748:
// once the controller is at its configured maxQueueDepth, a new scan request must be
// rejected with 503/ErrQueueFull instead of being queued, and a slot freed by a finished
// job must be usable by the next request.
func TestHTTPController_GenerateSBOM_QueueFull(t *testing.T) {
	c := (&HTTPController{
		scanService: services.NewMockScanService(true),
		workerPool:  workerpool.New(1),
	}).WithMaxQueueDepth(1)
	defer c.Shutdown(2 * time.Second)

	// Simulate one job already occupying the controller's only admission slot -- the same
	// state a real in-flight scan would leave pending in, without needing to synchronize
	// against a background goroutine.
	require.True(t, c.tryAdmit())

	router := gin.Default()
	router.POST("/v1/generateSBOM", c.GenerateSBOM)

	file, err := os.Open("../api/v1/testdata/scan.yaml")
	require.NoError(t, err)
	req, _ := http.NewRequest("POST", "/v1/generateSBOM", file)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusServiceUnavailable, w.Code, w.Body.String())

	// Freeing the slot must let the next request through.
	c.release()

	file2, err := os.Open("../api/v1/testdata/scan.yaml")
	require.NoError(t, err)
	req2, _ := http.NewRequest("POST", "/v1/generateSBOM", file2)
	w2 := httptest.NewRecorder()
	router.ServeHTTP(w2, req2)
	assert.Equal(t, http.StatusOK, w2.Code, w2.Body.String())
}

// TestHTTPController_ScanCP_QueueFull mirrors TestHTTPController_GenerateSBOM_QueueFull for
// ScanCP, which submits to the worker pool via its own closure rather than runTrackedScan
// (see runTrackedScan's doc comment) and so needs its own regression coverage that it
// respects admission control the same way.
func TestHTTPController_ScanCP_QueueFull(t *testing.T) {
	c := (&HTTPController{
		scanService: services.NewMockScanService(true),
		workerPool:  workerpool.New(1),
	}).WithMaxQueueDepth(1)
	defer c.Shutdown(2 * time.Second)

	require.True(t, c.tryAdmit())

	router := gin.Default()
	router.POST("/v1/scanCP", c.ScanCP)

	req, _ := http.NewRequest("POST", "/v1/scanCP", strings.NewReader(`{
		"wlid": "wlid://cluster-minikube/namespace-kube-system/daemonset-kube-proxy",
		"args": {"name": "daemonset-kube-proxy", "namespace": "kube-system"}
	}`))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusServiceUnavailable, w.Code, w.Body.String())
}

// TestHTTPController_MaxQueueDepth_ReleasesSlotAfterScanCompletes is an end-to-end regression
// test that runTrackedScan's deferred release() actually fires once a real (non-simulated)
// tracked scan finishes, not just that tryAdmit/release are individually correct.
func TestHTTPController_MaxQueueDepth_ReleasesSlotAfterScanCompletes(t *testing.T) {
	spy := &contextSpyScanService{generateSBOMCh: make(chan struct{})}
	c := (&HTTPController{
		scanService: spy,
		workerPool:  workerpool.New(1),
	}).WithMaxQueueDepth(1)
	defer c.Shutdown(2 * time.Second)

	router := gin.Default()
	router.POST("/v1/generateSBOM", c.GenerateSBOM)

	req, _ := http.NewRequest("POST", "/v1/generateSBOM", strings.NewReader(`{"jobID": "job-1"}`))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	select {
	case <-spy.generateSBOMCh:
	case <-time.After(1 * time.Second):
		t.Fatal("GenerateSBOM worker was not executed in time")
	}

	require.Eventually(t, func() bool { return c.pending.Load() == 0 }, time.Second, 5*time.Millisecond,
		"pending should drop back to 0 once the tracked scan's closure finishes")
}

// TestHTTPController_MetricsEndpoint_RecordsQueueFullRejection mirrors
// TestHTTPController_MetricsEndpoint_RecordsRejection for the queue_full rejection reason,
// proving it's recorded distinctly from too_many_requests/invalid_request rather than
// conflated with either.
func TestHTTPController_MetricsEndpoint_RecordsQueueFullRejection(t *testing.T) {
	c := (&HTTPController{
		scanService: services.NewMockScanService(true),
		workerPool:  workerpool.New(1),
	}).WithMaxQueueDepth(1)
	require.True(t, c.tryAdmit())

	m, err := metrics.New()
	require.NoError(t, err)
	c, err = c.WithMetrics(m)
	require.NoError(t, err)

	router := gin.Default()
	router.POST("/v1/generateSBOM", c.GenerateSBOM)
	router.GET("/metrics", gin.WrapH(m.Handler()))

	file, err := os.Open("../api/v1/testdata/scan.yaml")
	require.NoError(t, err)
	req, _ := http.NewRequest("POST", "/v1/generateSBOM", file)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	require.Equal(t, http.StatusServiceUnavailable, w.Code, w.Body.String())

	req, _ = http.NewRequest("GET", "/metrics", nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()
	assert.True(t, strings.Contains(body, `kubevuln_scan_rejections_total{endpoint="generateSBOM",reason="queue_full"} 1`), body)
	assert.False(t, strings.Contains(body, `reason="too_many_requests"`), body)
	assert.False(t, strings.Contains(body, `reason="invalid_request"`), body)
}

// TestHTTPController_GenerateSBOM_DuplicateJobIDRejected is a regression test for #856:
// submitting a jobID that already belongs to a job still queued or running must be
// rejected with 409, not silently accepted -- accepting it would let the new request
// reset the first job's tracking record out from under it via recordAccepted.
func TestHTTPController_GenerateSBOM_DuplicateJobIDRejected(t *testing.T) {
	c := (&HTTPController{
		scanService: services.NewMockScanService(true),
		workerPool:  workerpool.New(1),
	}).WithMaxQueueDepth(1)
	defer c.Shutdown(2 * time.Second)

	// Simulate a job already accepted under the same jobID the request below uses, without
	// needing to synchronize against a background goroutine -- the same style
	// TestHTTPController_GenerateSBOM_QueueFull uses for tryAdmit. maxQueueDepth is bounded
	// here specifically so pending is actually exercised: with the default unbounded queue,
	// tryAdmit/release are no-ops and pending stays 0 regardless of whether the rejection
	// path is correct.
	require.True(t, c.ensureStatuses().recordAccepted("job-dup", "generateSBOM"))

	router := gin.Default()
	router.POST("/v1/generateSBOM", c.GenerateSBOM)

	req, _ := http.NewRequest("POST", "/v1/generateSBOM", strings.NewReader(`{"imageTag":"nginx:1.24","imageHash":"sha256:dup","jobID":"job-dup"}`))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusConflict, w.Code, w.Body.String())

	// admitJob's isActive precedence check catches this before admitQueueSlot ever reserves
	// a slot for it, so the controller's one slot of capacity must still be free afterward.
	require.Eventually(t, func() bool { return c.pending.Load() == 0 }, time.Second, 5*time.Millisecond,
		"a duplicate rejection must not consume the controller's admission capacity")

	status, ok := c.ensureStatuses().get("job-dup")
	require.True(t, ok)
	assert.Equal(t, domain.ScanStateQueued, status.State, "the original job's record must be untouched by the rejected duplicate")
}

// TestHTTPController_DuplicateJobID_TakesPrecedenceOverQueueFull covers the ordering CodeRabbit
// flagged on #857: if the job occupying the controller's one and only admission slot is the
// same jobID a new request reuses, admitQueueSlot alone would reject that request as 503
// queue-full without ever getting a chance to diagnose it as a 409 duplicate, since capacity
// is genuinely exhausted. admitJob's isActive check runs before admitQueueSlot specifically
// so this case is still reported as a duplicate, which more precisely describes the actual
// conflict and doesn't imply retrying with a fresh jobID would also be rejected.
func TestHTTPController_DuplicateJobID_TakesPrecedenceOverQueueFull(t *testing.T) {
	c := (&HTTPController{
		scanService: services.NewMockScanService(true),
		workerPool:  workerpool.New(1),
	}).WithMaxQueueDepth(1)
	defer c.Shutdown(2 * time.Second)

	// The one and only admission slot is occupied by "job-dup" itself, exhausting capacity.
	require.True(t, c.tryAdmit())
	require.True(t, c.ensureStatuses().recordAccepted("job-dup", "generateSBOM"))

	router := gin.Default()
	router.POST("/v1/generateSBOM", c.GenerateSBOM)

	req, _ := http.NewRequest("POST", "/v1/generateSBOM", strings.NewReader(`{"imageTag":"nginx:1.24","imageHash":"sha256:dup","jobID":"job-dup"}`))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusConflict, w.Code, w.Body.String(),
		"a jobID collision must be reported as 409, not 503, even when it also happens to be the request holding the only free slot")

	// A different, non-duplicate jobID must still see the queue as genuinely full.
	req2, _ := http.NewRequest("POST", "/v1/generateSBOM", strings.NewReader(`{"imageTag":"nginx:1.24","imageHash":"sha256:other","jobID":"job-other"}`))
	w2 := httptest.NewRecorder()
	router.ServeHTTP(w2, req2)
	assert.Equal(t, http.StatusServiceUnavailable, w2.Code, w2.Body.String())
}

// TestHTTPController_DuplicateJobID_PreservesFirstJobOutcome end-to-end reproduces the
// scenario from #856: a jobID reused while its first job is genuinely still running (not
// just simulated store state) must be rejected, and the first job's real outcome must reach
// ScanStatus uncorrupted once it finishes -- not silently overwritten by the duplicate the
// way it would have been before recordAccepted rejected the re-admission.
func TestHTTPController_DuplicateJobID_PreservesFirstJobOutcome(t *testing.T) {
	blocked := make(chan struct{})
	started := make(chan struct{}, 1)
	c := NewHTTPController(statusFlowScanService{
		MockScanService: services.NewMockScanService(true),
		err:             &domain.ScanError{Reason: scanfailure.ReasonCVEMatchingFailed, Err: errors.New("boom")},
		blockCh:         blocked,
		startedCh:       started,
	}, 1)
	t.Cleanup(func() {
		select {
		case <-blocked:
		default:
			close(blocked)
		}
	})

	router := gin.Default()
	router.POST("/v1/generateSBOM", c.GenerateSBOM)
	router.GET("/v1/scanStatus/:jobID", c.ScanStatus)

	firstReq, _ := http.NewRequest("POST", "/v1/generateSBOM", strings.NewReader(`{"imageTag":"nginx:1.24","imageHash":"sha256:4","jobID":"job-reused"}`))
	firstW := httptest.NewRecorder()
	router.ServeHTTP(firstW, firstReq)
	require.Equal(t, http.StatusOK, firstW.Code, firstW.Body.String())

	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("first job's scan was not started in time")
	}

	// The first job is now genuinely Running (blocked inside GenerateSBOM). A second request
	// reusing the same jobID -- a retry, redelivery, or caller bug -- must be rejected rather
	// than resetting the first job's record back to Queued.
	dupReq, _ := http.NewRequest("POST", "/v1/generateSBOM", strings.NewReader(`{"imageTag":"nginx:1.24","imageHash":"sha256:4","jobID":"job-reused"}`))
	dupW := httptest.NewRecorder()
	router.ServeHTTP(dupW, dupReq)
	require.Equal(t, http.StatusConflict, dupW.Code, dupW.Body.String())

	close(blocked)

	var status domain.ScanStatus
	require.Eventually(t, func() bool {
		req, _ := http.NewRequest("GET", "/v1/scanStatus/job-reused", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			return false
		}
		if err := json.Unmarshal(w.Body.Bytes(), &status); err != nil {
			return false
		}
		return status.State == domain.ScanStateFailed
	}, time.Second, 10*time.Millisecond)

	assert.Equal(t, scanfailure.ReasonCVEMatchingFailed, status.Reason,
		"the first job's real outcome must reach ScanStatus, not be silently dropped by the rejected duplicate")
}

// TestHTTPController_MetricsEndpoint_RecordsDuplicateJobIDRejection mirrors
// TestHTTPController_MetricsEndpoint_RecordsQueueFullRejection for the duplicate_job_id
// rejection reason, proving it's recorded distinctly from the other rejection reasons.
func TestHTTPController_MetricsEndpoint_RecordsDuplicateJobIDRejection(t *testing.T) {
	c := &HTTPController{
		scanService: services.NewMockScanService(true),
		workerPool:  workerpool.New(1),
	}
	require.True(t, c.ensureStatuses().recordAccepted("job-dup", "generateSBOM"))

	m, err := metrics.New()
	require.NoError(t, err)
	c, err = c.WithMetrics(m)
	require.NoError(t, err)

	router := gin.Default()
	router.POST("/v1/generateSBOM", c.GenerateSBOM)
	router.GET("/metrics", gin.WrapH(m.Handler()))

	req, _ := http.NewRequest("POST", "/v1/generateSBOM", strings.NewReader(`{"imageTag":"nginx:1.24","imageHash":"sha256:dup","jobID":"job-dup"}`))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	require.Equal(t, http.StatusConflict, w.Code, w.Body.String())

	req, _ = http.NewRequest("GET", "/metrics", nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()
	assert.True(t, strings.Contains(body, `kubevuln_scan_rejections_total{endpoint="generateSBOM",reason="duplicate_job_id"} 1`), body)
	assert.False(t, strings.Contains(body, `reason="queue_full"`), body)
	assert.False(t, strings.Contains(body, `reason="invalid_request"`), body)
}

// The other three endpoints each cover a body that will not bind; ScanCP did not, which
// left the one handler whose worker closure is its own copy unexercised on that path.
func TestHTTPController_ScanCP_InvalidRequest(t *testing.T) {
	c := HTTPController{
		scanService: services.NewMockScanService(true),
		workerPool:  workerpool.New(1),
	}
	defer c.Shutdown(5 * time.Second)

	router := gin.Default()
	path := "/v1/scanApplicationProfile"
	router.POST(path, c.ScanCP)

	file, err := os.Open("../api/v1/testdata/scan-invalid.yaml")
	require.NoError(t, err)
	defer file.Close()
	req, _ := http.NewRequest("POST", path, file)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Equal(t, "{\"status\":400,\"title\":\"Bad Request\"}", w.Body.String())
}
