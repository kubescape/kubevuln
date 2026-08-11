package controllers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	wssc "github.com/armosec/armoapi-go/apis"
	"github.com/armosec/armoapi-go/scanfailure"
	"github.com/docker/docker/api/types/registry"
	"github.com/gammazero/workerpool"
	"github.com/gin-gonic/gin"
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

func TestValidationStatusCode(t *testing.T) {
	assert.Equal(t, http.StatusTooManyRequests, validationStatusCode(domain.ErrTooManyRequests))
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
	c := NewHTTPController(services.NewMockScanService(true), 1)
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
	err error
}

func (s scanErrorService) GenerateSBOM(context.Context) error { return s.err }
func (s scanErrorService) ScanCVE(context.Context) error      { return s.err }
func (s scanErrorService) ScanRegistry(context.Context) error { return s.err }

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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var scanErr error = &domain.ScanError{Reason: tt.wantReason, Err: errors.New("boom")}
			if tt.unclassified {
				scanErr = errors.New("boom")
			}
			c := &HTTPController{
				scanService: scanErrorService{MockScanService: services.NewMockScanService(true), err: scanErr},
				workerPool:  workerpool.New(1),
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

// ImageSlug is the storage key for the SBOM and the CVE manifest, so equivalent references to
// the same image must produce the same slug. Deriving it from the raw tag gave each reference
// form its own key, so every form missed the cache and regenerated the SBOM from scratch, and
// the rate-limit and exception caches (which key on the normalized reference) disagreed with
// storage about which image was in play.
func Test_registryScanCommandToScanCommand_SlugIsStableAcrossEquivalentReferences(t *testing.T) {
	equivalent := []string{
		"nginx",
		"nginx:latest",
		"library/nginx:latest",
		"docker.io/library/nginx:latest",
		"index.docker.io/library/nginx:latest",
	}

	var slugs []string
	for _, ref := range equivalent {
		cmd := registryScanCommandToScanCommand(wssc.RegistryScanCommand{
			ImageScanParams: wssc.ImageScanParams{ImageTag: ref},
		})
		assert.NotEmpty(t, cmd.ImageSlug, "slug must resolve for %q", ref)
		slugs = append(slugs, cmd.ImageSlug)
	}

	for i, got := range slugs {
		assert.Equal(t, slugs[0], got,
			"%q and %q are the same image and must share a storage key", equivalent[0], equivalent[i])
	}
}

// A different image must still get a different key.
func Test_registryScanCommandToScanCommand_SlugDistinguishesImages(t *testing.T) {
	slugFor := func(ref string) string {
		return registryScanCommandToScanCommand(wssc.RegistryScanCommand{
			ImageScanParams: wssc.ImageScanParams{ImageTag: ref},
		}).ImageSlug
	}

	assert.NotEqual(t, slugFor("nginx:latest"), slugFor("nginx:1.25"))
	assert.NotEqual(t, slugFor("nginx:latest"), slugFor("alpine:latest"))
	assert.NotEqual(t, slugFor("docker.io/library/nginx:latest"), slugFor("quay.io/library/nginx:latest"))
}
