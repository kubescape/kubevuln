package controllers

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/gammazero/workerpool"
	"github.com/gin-gonic/gin"
	"github.com/kubescape/kubevuln/core/ports"
	"github.com/kubescape/kubevuln/core/services"
	"github.com/kubescape/kubevuln/internal/tools"
	"gotest.tools/v3/assert"
)

func TestHTTPController_Alive(t *testing.T) {
	c := HTTPController{}
	router := gin.Default()
	path := "/v1/liveness"
	router.GET(path, c.Alive)
	req, _ := http.NewRequest("GET", path, nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Assert(t, http.StatusOK == w.Code, w.Code)
	assert.Assert(t, w.Body.String() == "{\"status\":200,\"title\":\"OK\"}", w.Body.String())
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
			tools.EnsureSetup(t, err == nil)
			req, _ := http.NewRequest("POST", path, file)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			assert.Assert(t, tt.expectedCode == w.Code, w.Code)
			assert.Assert(t, tt.expectedBody == w.Body.String(), w.Body.String())
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
			assert.Assert(t, tt.expectedCode == w.Code, w.Code)
			assert.Assert(t, tt.expectedBody == w.Body.String(), w.Body.String())
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
			tools.EnsureSetup(t, err == nil)
			req, _ := http.NewRequest("POST", path, file)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			assert.Assert(t, tt.expectedCode == w.Code, w.Code)
			assert.Assert(t, tt.expectedBody == w.Body.String(), w.Body.String())
		})
	}
}
