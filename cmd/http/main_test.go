package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/armosec/armoapi-go/apis"
	"github.com/gin-gonic/gin"
	"github.com/kubescape/kubevuln/adapters"
	"github.com/kubescape/kubevuln/controllers"
	"github.com/kubescape/kubevuln/core/ports"
	"github.com/kubescape/kubevuln/core/services"
	"github.com/kubescape/kubevuln/internal/tools"
	"github.com/kubescape/kubevuln/repositories"
	"gotest.tools/v3/assert"
)

func TestScan(t *testing.T) {
	tests := []struct {
		name         string
		yamlFile     string
		expectedCode int
		expectedBody string
		sbomRepo     ports.SBOMRepository
		cveRepo      ports.CVERepository
	}{
		{
			"phase 1: valid scan command succeeds and reports CVE",
			"../../api/v1/testdata/scan.yaml",
			200,
			"{\"detail\":\"Wlid=wlid://cluster-minikube/namespace-kube-system/daemonset-kube-proxy, ImageHash=k8s.gcr.io/kube-proxy@sha256:c1b135231b5b1a6799346cd701da4b59e5b7ef8e694ec7b04fb23b8dbe144137\",\"status\":200,\"title\":\"OK\"}",
			repositories.NewBrokenStorage(),
			repositories.NewBrokenStorage(),
		},
		{
			"phase 1: missing fields",
			"../../api/v1/testdata/scan-incomplete.yaml",
			500,
			"{\"detail\":\"Wlid=wlid://cluster-bez-longrun3/namespace-kube-system/deployment-coredns, ImageHash=\",\"status\":500,\"title\":\"Internal Server Error\"}",
			repositories.NewBrokenStorage(),
			repositories.NewBrokenStorage(),
		},
		{
			"phase 1: invalid yaml",
			"../../api/v1/testdata/scan-invalid.yaml",
			400,
			"{\"status\":400,\"title\":\"Bad Request\"}",
			repositories.NewBrokenStorage(),
			repositories.NewBrokenStorage(),
		},
		{
			"phase 2: valid scan command succeeds and reports CVE",
			"../../api/v1/testdata/scan.yaml",
			200,
			"{\"detail\":\"Wlid=wlid://cluster-minikube/namespace-kube-system/daemonset-kube-proxy, ImageHash=k8s.gcr.io/kube-proxy@sha256:c1b135231b5b1a6799346cd701da4b59e5b7ef8e694ec7b04fb23b8dbe144137\",\"status\":200,\"title\":\"OK\"}",
			repositories.NewMemoryStorage(),
			repositories.NewMemoryStorage(),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			repository := repositories.NewBrokenStorage()
			sbomAdapter := adapters.NewMockSBOMAdapter()
			cveAdapter := adapters.NewMockCVEAdapter()
			platform := adapters.NewMockPlatform()
			service := services.NewScanService(sbomAdapter, repository, cveAdapter, repository, platform)
			controller := controllers.NewHTTPController(service, 2)

			router := gin.Default()

			router.GET("/v1/liveness", controller.Alive)
			router.GET("/v1/readiness", controller.Ready)

			group := router.Group(apis.WebsocketScanCommandVersion)
			{
				group.POST("/"+apis.SBOMCalculationCommandPath, controller.GenerateSBOM)
				group.POST("/"+apis.WebsocketScanCommandPath, controller.ScanCVE)
			}

			req, _ := http.NewRequest("GET", "/v1/liveness", nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			req, _ = http.NewRequest("GET", "/v1/readiness", nil)
			w = httptest.NewRecorder()
			router.ServeHTTP(w, req)

			file, err := os.Open(test.yamlFile)
			tools.EnsureSetup(t, err == nil)
			req, _ = http.NewRequest("POST", "/v1/generateSBOM", file)
			w = httptest.NewRecorder()
			router.ServeHTTP(w, req)

			file, err = os.Open(test.yamlFile)
			tools.EnsureSetup(t, err == nil)
			req, _ = http.NewRequest("POST", "/v1/scanImage", file)
			w = httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Assert(t, test.expectedCode == w.Code)
			assert.Assert(t, test.expectedBody == w.Body.String(), w.Body.String())

			controller.Shutdown()
		})
	}
}
