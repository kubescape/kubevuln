package vexsource

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kubescape/kubevuln/internal/safefetch"
	"github.com/stretchr/testify/require"
)

func TestIngestorIngest(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(validOpenVEX))
	}))
	defer server.Close()

	ingestor := Ingestor{
		Fetcher: &safefetch.Fetcher{
			Client:   server.Client(),
			MaxBytes: 1 << 20,
		},
	}

	document, err := ingestor.Ingest(
		context.Background(),
		Source{URL: server.URL},
	)

	require.NoError(t, err)
	require.Equal(t, server.URL, document.URL)
	require.JSONEq(t, validOpenVEX, string(document.Data))
}
