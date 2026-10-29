package sbomreuse

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/kubevuln/internal/metrics"
	"github.com/stretchr/testify/require"
)

func TestAcquireMetricsCountPartialResponseBytes(t *testing.T) {
	m, err := metrics.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = m.Shutdown(context.Background()) })
	var partialResponses atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v2/" {
			w.WriteHeader(http.StatusOK)
			return
		}
		partialResponses.Add(1)
		w.Header().Set("Content-Length", "100")
		_, _ = io.WriteString(w, "partial")
	}))
	defer server.Close()
	repository := strings.TrimPrefix(server.URL, "http://") + "/team/image"
	p, _ := testPolicy(t, repository)
	policy, err := CompilePolicy(p)
	require.NoError(t, err)
	_, err = NewProvider(policy).Acquire(context.Background(), "image", repository+"@sha256:"+strings.Repeat("a", 64), domain.RegistryOptions{
		InsecureUseHTTP: true,
		Credentials:     []domain.RegistryCredentials{{Authority: strings.TrimPrefix(server.URL, "http://"), Username: "test-user", Password: "test-password"}},
	})
	require.Error(t, err)
	require.Positive(t, partialResponses.Load())
	recorder := httptest.NewRecorder()
	m.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	require.Contains(t, recorder.Body.String(), fmt.Sprintf("kubevuln_sbom_import_bytes_total %d\n", 7*partialResponses.Load()))
	require.Contains(t, recorder.Body.String(), `kubevuln_sbom_import_attempts_total{result="resolution"} 1`)
}
