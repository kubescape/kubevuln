package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/armosec/armoapi-go/apis"
	"github.com/gin-gonic/gin"
	"github.com/kubescape/kubevuln/adapters"
	"github.com/kubescape/kubevuln/controllers"
	"github.com/kubescape/kubevuln/core/services"
	"github.com/kubescape/kubevuln/repositories"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestProductionBuildExcludesDockerFixture is a regression test for #929: adapters/v1's
// Docker-container-backed grype-DB test fixture (NewGrypeAdapterFixedDB and friends, in
// adapters/v1/grype_docker_fixture.go) must never be linked into the production kubevuln
// binary. Nothing in cmd/http calls it, but its testcontainers-go/docker/docker dependency
// used to be compiled in regardless -- carrying whatever CVEs that tree currently has for a
// binary that can never actually reach them. Because the fixture is gated behind the `dockerfixture`
// build tag, an untagged `go list -deps .` must exclude both packages by default.
func TestProductionBuildExcludesDockerFixture(t *testing.T) {
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go toolchain not on PATH")
	}

	// go list -deps walks the whole module graph; on a cold build cache this can take well
	// over a minute, so the bound here is generous rather than tight -- it exists only to
	// stop a genuinely hung process, not to race a normal resolution.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	// "." resolves relative to this test's own package directory (cmd/http), which is the
	// package go test sets as the working directory. Target the exact production Linux build.
	cmd := exec.CommandContext(ctx, goBin, "list", "-deps", ".")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH=amd64")
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "go list -deps failed: %s", out)

	deps := string(out)
	assert.NotContains(t, deps, "github.com/testcontainers/testcontainers-go",
		"the production build must not link the Docker-container-backed grype test fixture")
	assert.NotContains(t, deps, "github.com/docker/docker/client",
		"the production build must not link docker/docker/client (currently carries unfixed CVEs, see #929)")
}

func TestIsRiskAcceptanceActive(t *testing.T) {
	storage := repositories.NewFakeAPIServerStorage("kubescape")

	tests := []struct {
		name           string
		storage        *repositories.APIServerStore
		riskAcceptance bool
		want           bool
	}{
		{
			name:           "storage configured and flag enabled",
			storage:        storage,
			riskAcceptance: true,
			want:           true,
		},
		{
			name:           "storage configured but flag disabled",
			storage:        storage,
			riskAcceptance: false,
			want:           false,
		},
		{
			name:           "flag enabled but storage not configured",
			storage:        nil,
			riskAcceptance: true,
			want:           false,
		},
		{
			name:           "neither storage nor flag configured",
			storage:        nil,
			riskAcceptance: false,
			want:           false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isRiskAcceptanceActive(tt.storage, tt.riskAcceptance))
		})
	}
}

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
			400,
			"{\"detail\":\"Wlid=wlid://cluster-bez-longrun3/namespace-kube-system/deployment-coredns, ImageHash=k8s.gcr.io/coredns/coredns:v1.8.6\",\"status\":400,\"title\":\"Bad Request\"}",
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
			platform := adapters.NewMockPlatform(true, nil)
			relevancyProvider := adapters.NewMockRelevancyAdapter()
			service := services.NewScanService(sbomAdapter, repository, cveAdapter, repository, platform, relevancyProvider, test.storage, false, true, false, false)
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

			controller.Shutdown(5 * time.Second)
		})
	}
}
