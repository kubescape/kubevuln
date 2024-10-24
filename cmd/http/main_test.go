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
	"github.com/kubescape/kubevuln/core/services"
	"github.com/kubescape/kubevuln/repositories"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestScan(t *testing.T) {
	tests := []struct {
		name         string
		yamlFile     string
		url          string
		expectedCode int
		expectedBody string
		storage      bool
	}{
		{
			"generate SBOM no storage",
			"../../api/v1/testdata/scan.yaml",
			"/v1/generateSBOM",
			200,
			"{\"detail\":\"ImageHash=k8s.gcr.io/kube-proxy@sha256:c1b135231b5b1a6799346cd701da4b59e5b7ef8e694ec7b04fb23b8dbe144137\",\"status\":200,\"title\":\"OK\"}",
			false,
		},
		{
			"generate SBOM storage",
			"../../api/v1/testdata/scan.yaml",
			"/v1/generateSBOM",
			200,
			"{\"detail\":\"ImageHash=k8s.gcr.io/kube-proxy@sha256:c1b135231b5b1a6799346cd701da4b59e5b7ef8e694ec7b04fb23b8dbe144137\",\"status\":200,\"title\":\"OK\"}",
			true,
		},
		{
			"phase 1: valid scan command succeeds and reports CVE",
			"../../api/v1/testdata/scan.yaml",
			"/v1/scanImage",
			200,
			"{\"detail\":\"Wlid=wlid://cluster-minikube/namespace-kube-system/daemonset-kube-proxy, ImageHash=k8s.gcr.io/kube-proxy@sha256:c1b135231b5b1a6799346cd701da4b59e5b7ef8e694ec7b04fb23b8dbe144137\",\"status\":200,\"title\":\"OK\"}",
			false,
		},
		{
			"phase 1: missing fields",
			"../../api/v1/testdata/scan-incomplete.yaml",
			"/v1/scanImage",
			500,
			"{\"detail\":\"Wlid=wlid://cluster-bez-longrun3/namespace-kube-system/deployment-coredns, ImageHash=\",\"status\":500,\"title\":\"Internal Server Error\"}",
			false,
		},
		{
			"phase 1: invalid yaml",
			"../../api/v1/testdata/scan-invalid.yaml",
			"/v1/scanImage",
			400,
			"{\"status\":400,\"title\":\"Bad Request\"}",
			false,
		},
		{
			"phase 2: valid scan command succeeds and reports CVE",
			"../../api/v1/testdata/scan.yaml",
			"/v1/scanImage",
			200,
			"{\"detail\":\"Wlid=wlid://cluster-minikube/namespace-kube-system/daemonset-kube-proxy, ImageHash=k8s.gcr.io/kube-proxy@sha256:c1b135231b5b1a6799346cd701da4b59e5b7ef8e694ec7b04fb23b8dbe144137\",\"status\":200,\"title\":\"OK\"}",
			true,
		},
		{
			"registry scan: valid scan command succeeds and reports CVE",
			"../../api/v1/testdata/scan-registry.yaml",
			"/v1/scanRegistryImage",
			200,
			"{\"detail\":\"ImageTag=k8s.gcr.io/kube-proxy:v1.24.3\",\"status\":200,\"title\":\"OK\"}",
			false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			repository := repositories.NewFakeAPIServerStorage("kubescape")
			sbomAdapter := adapters.NewMockSBOMAdapter(false, false, false)
			cveAdapter := adapters.NewMockCVEAdapter()
			platform := adapters.NewMockPlatform(true)
			service := services.NewScanService(sbomAdapter, repository, cveAdapter, repository, platform, test.storage, false, true)
			controller := controllers.NewHTTPController(service, 2)

			router := gin.Default()

			router.GET("/v1/liveness", controller.Alive)
			router.GET("/v1/readiness", controller.Ready)

			group := router.Group(apis.VulnerabilityScanCommandVersion)
			{
				group.POST("/"+apis.SBOMCalculationCommandPath, controller.GenerateSBOM)
				group.POST("/"+apis.ContainerScanCommandPath, controller.ScanCVE)
				group.POST("/"+apis.RegistryScanCommandPath, controller.ScanRegistry)
			}

			req, _ := http.NewRequest("GET", "/v1/liveness", nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			req, _ = http.NewRequest("GET", "/v1/readiness", nil)
			w = httptest.NewRecorder()
			router.ServeHTTP(w, req)

			file, err := os.Open(test.yamlFile)
			require.NoError(t, err)
			req, _ = http.NewRequest("POST", test.url, file)
			w = httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, test.expectedCode, w.Code, w.Code)
			assert.Equal(t, test.expectedBody, w.Body.String(), w.Body.String())

			controller.Shutdown()
		})
	}
}
