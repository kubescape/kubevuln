package controllers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	wssc "github.com/armosec/armoapi-go/apis"
	"github.com/docker/docker/api/types/registry"
	"github.com/gammazero/workerpool"
	"github.com/gin-gonic/gin"
	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/kubevuln/core/ports"
	"github.com/kubescape/kubevuln/core/services"
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
			expectedCode: http.StatusInternalServerError,
			expectedBody: "{\"detail\":\"ImageHash=k8s.gcr.io/kube-proxy@sha256:c1b135231b5b1a6799346cd701da4b59e5b7ef8e694ec7b04fb23b8dbe144137\",\"status\":500,\"title\":\"Internal Server Error\"}",
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
			expectedCode: http.StatusInternalServerError,
			expectedBody: "{\"detail\":\"Wlid=wlid://cluster-minikube/namespace-kube-system/daemonset-kube-proxy, ImageHash=k8s.gcr.io/kube-proxy@sha256:c1b135231b5b1a6799346cd701da4b59e5b7ef8e694ec7b04fb23b8dbe144137\",\"status\":500,\"title\":\"Internal Server Error\"}",
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
			expectedCode: http.StatusInternalServerError,
			expectedBody: "{\"detail\":\"ImageTag=k8s.gcr.io/kube-proxy:v1.24.3\",\"status\":500,\"title\":\"Internal Server Error\"}",
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
	defer c.Shutdown()

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

