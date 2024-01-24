package controllers

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	wssc "github.com/armosec/armoapi-go/apis"
	"github.com/docker/docker/api/types/registry"
	"github.com/gammazero/workerpool"
	"github.com/gin-gonic/gin"
	"github.com/kubescape/kubevuln/core/ports"
	"github.com/kubescape/kubevuln/core/services"
	"github.com/kubescape/kubevuln/internal/tools"
	"github.com/stretchr/testify/assert"
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
			tools.EnsureSetup(t, err == nil)
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
			tools.EnsureSetup(t, err == nil)
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
			tools.EnsureSetup(t, err == nil)
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
