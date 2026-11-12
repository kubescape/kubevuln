package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/armosec/armoapi-go/apis"
	"github.com/kubescape/kubevuln/adapters"
	"github.com/kubescape/kubevuln/controllers"
	"github.com/kubescape/kubevuln/core/services"
	"github.com/kubescape/kubevuln/repositories"
	"github.com/kubescape/storage/pkg/apiauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestApiAuthRoute_Table(t *testing.T) {
	create := apiauth.Attributes{Group: apiGroup, Resource: apiResource, Verb: "create"}
	get := apiauth.Attributes{Group: apiGroup, Resource: apiResource, Verb: "get"}
	v1 := "/" + apis.VulnerabilityScanCommandVersion + "/"
	tests := []struct {
		method, path string
		want         apiauth.Attributes
		protected    bool
	}{
		{"POST", v1 + apis.ContainerScanCommandPath, create, true},
		{"GET", v1 + apis.ContainerScanCommandPath, create, true},
		{"POST", v1 + apis.RegistryScanCommandPath, create, true},
		{"POST", v1 + apis.ApplicationProfileScanCommandPath, create, true},
		{"POST", v1 + apis.SBOMCalculationCommandPath, create, true},
		{"GET", v1 + "scanStatus/job-1", get, true},
		{"GET", v1 + "diagnostics", get, true},
		{"GET", v1 + "other", get, true},
		{"POST", v1 + "other", get, true},
		{"GET", "/metrics", apiauth.Attributes{}, false},
		{"GET", v1 + "liveness", apiauth.Attributes{}, false},
		{"GET", v1 + "readiness", apiauth.Attributes{}, false},
	}
	for _, tc := range tests {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			r := httptest.NewRequest(tc.method, tc.path, nil)
			got, protected := apiAuthRoute(r)
			assert.Equal(t, tc.protected, protected)
			if tc.protected {
				assert.Equal(t, tc.want, got)
			}
		})
	}
}

func TestNewAPIAuth_RequiresPodNamespace(t *testing.T) {
	t.Setenv(apiauth.DisabledEnv, "")
	t.Setenv("POD_NAMESPACE", "")
	_, err := newAPIAuth(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "POD_NAMESPACE must be set")
}

func TestNewAPIAuth_Disabled(t *testing.T) {
	t.Setenv(apiauth.DisabledEnv, "true")
	auth, err := newAPIAuth(context.Background())
	require.NoError(t, err)
	require.NotNil(t, auth)
}

func TestRouter_ProbesAndMetricsOpen_ScansProtected(t *testing.T) {
	repository := repositories.NewFakeAPIServerStorage("kubescape")
	service := services.NewScanService(adapters.NewMockSBOMAdapter(false, false, false), repository, adapters.NewMockCVEAdapter(), repository, adapters.NewMockPlatform(true, nil), adapters.NewMockRelevancyAdapter(), false, false, true, false, false)
	controller := controllers.NewHTTPController(service, 2)
	deny := ginWrap(func(http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusUnauthorized) })
	})
	metrics := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	router := newRouter(controller, metrics, deny)

	do := func(method, path string) int {
		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest(method, path, strings.NewReader("{}")))
		return w.Code
	}
	assert.NotEqual(t, http.StatusUnauthorized, do("GET", "/v1/liveness"))
	assert.NotEqual(t, http.StatusUnauthorized, do("GET", "/v1/readiness"))
	assert.NotEqual(t, http.StatusUnauthorized, do("GET", "/metrics"))
	assert.Equal(t, http.StatusUnauthorized, do("POST", "/v1/scanImage"))
	assert.Equal(t, http.StatusUnauthorized, do("GET", "/v1/diagnostics"))
	assert.Equal(t, http.StatusUnauthorized, do("GET", "/v1/scanStatus/x"))
}
