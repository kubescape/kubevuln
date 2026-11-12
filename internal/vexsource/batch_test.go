package vexsource

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/kubescape/kubevuln/internal/safefetch"
	"github.com/stretchr/testify/require"
)

func TestIngestorIngestBatchKeepsSuccessfulSources(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/valid", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(validOpenVEX))
	})
	mux.HandleFunc("/invalid", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "upstream unavailable", http.StatusServiceUnavailable)
	})
	server := httptest.NewTLSServer(mux)
	defer server.Close()

	ingestor := Ingestor{
		Fetcher: &safefetch.Fetcher{
			Client:   server.Client(),
			MaxBytes: 1 << 20,
		},
	}

	batch := ingestor.IngestBatch(context.Background(), []Source{
		{URL: server.URL + "/valid"},
		{URL: server.URL + "/invalid"},
	})

	require.Len(t, batch.Documents, 1)
	require.Len(t, batch.Failures, 1)
	require.Equal(t, server.URL+"/invalid", batch.Failures[0].URL)
	require.ErrorContains(t, batch.Err(), server.URL+"/invalid")

	stagedPath := batch.Documents[0].Path
	_, err := os.Stat(stagedPath)
	require.NoError(t, err)

	batch.Cleanup()
	_, err = os.Stat(stagedPath)
	require.ErrorIs(t, err, os.ErrNotExist)

	// Cleanup is intentionally idempotent for deferred and error paths.
	batch.Cleanup()
}

func TestIngestorIngestBatchEmptySources(t *testing.T) {
	batch := (Ingestor{}).IngestBatch(context.Background(), nil)

	require.Empty(t, batch.Documents)
	require.Empty(t, batch.Failures)
	require.NoError(t, batch.Err())
	batch.Cleanup()
}
