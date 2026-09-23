package vexsource

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kubescape/kubevuln/internal/safefetch"
	"github.com/kubescape/kubevuln/internal/vexvalidate"
	"github.com/stretchr/testify/require"
)

const validOpenVEX = `{
"@context": "https://openvex.dev/ns/v0.2.0",
"@id": "https://example.com/vex-1",
"author": "test",
"timestamp": "2026-01-01T00:00:00Z",
"version": 1,
"statements": [
{
"vulnerability": {"name": "CVE-2021-44228"},
"products": [{"@id": "pkg:maven/org.apache.logging.log4j/log4j-core@2.17.0"}],
"status": "not_affected",
"justification": "vulnerable_code_not_present"
}
]
}`

func TestSourceFetch(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(validOpenVEX))
	}))
	defer server.Close()

	source := Source{URL: server.URL}

	fetcher := &safefetch.Fetcher{
		Client:   server.Client(),
		MaxBytes: 1 << 20,
	}

	document, err := source.Fetch(context.Background(), fetcher)

	require.NoError(t, err)
	require.Equal(t, source.URL, document.URL)
	require.JSONEq(t, validOpenVEX, string(document.Data))
}

func TestSourceFetch_EmptyURL(t *testing.T) {
	source := Source{}

	_, err := source.Fetch(context.Background(), safefetch.New())

	require.EqualError(t, err, "vexsource: URL is empty")
}

func TestSourceFetch_NilFetcher(t *testing.T) {
	source := Source{URL: "https://example.com/vex.json"}

	_, err := source.Fetch(context.Background(), nil)

	require.EqualError(t, err, "vexsource: fetcher is nil")
}

func TestSourceFetch_FetchError(t *testing.T) {
	source := Source{URL: "http://example.com/vex.json"}

	_, err := source.Fetch(context.Background(), safefetch.New())

	require.Error(t, err)
}

func TestSourceFetch_InvalidVEX(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"invalid":"vex"}`))
	}))
	defer server.Close()

	source := Source{URL: server.URL}

	fetcher := &safefetch.Fetcher{
		Client:   server.Client(),
		MaxBytes: 1 << 20,
	}

	_, err := source.Fetch(context.Background(), fetcher)

	require.Error(t, err)
	require.True(t, errors.Is(err, vexvalidate.ErrInvalidContext))
}
