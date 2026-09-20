package vexsource

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/kubescape/kubevuln/internal/safefetch"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const validOpenVEX = `{
    "@context": "https://openvex.dev/ns/v0.2.0",
    "statements": [{
        "vulnerability": {"name": "CVE-2026-0001"},
        "products": [{"identifiers": {"purl": "pkg:oci/example@sha256:abc"}}],
        "status": "fixed"
    }]
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

	doc, cleanup, err := source.Fetch(context.Background(), fetcher)
	require.NoError(t, err)
	require.NotNil(t, cleanup)
	defer cleanup()

	assert.Equal(t, "openvex", string(doc.Format))
	assert.NotEmpty(t, doc.Path)

	data, err := os.ReadFile(doc.Path)
	require.NoError(t, err)
	assert.JSONEq(t, validOpenVEX, string(data))

	_, err = os.Stat(doc.Path)
	require.NoError(t, err)
}

func TestSourceFetchRejectsInvalidVEX(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"not": "vex"}`))
	}))
	defer server.Close()

	source := Source{URL: server.URL}
	fetcher := &safefetch.Fetcher{
		Client:   server.Client(),
		MaxBytes: 1 << 20,
	}

	doc, cleanup, err := source.Fetch(context.Background(), fetcher)

	require.Error(t, err)
	assert.Empty(t, doc.Path)
	assert.NotNil(t, cleanup)
}

func TestSourceFetchRequiresURL(t *testing.T) {
	source := Source{}

	doc, cleanup, err := source.Fetch(context.Background(), safefetch.New())

	require.Error(t, err)
	assert.Empty(t, doc.Path)
	assert.NotNil(t, cleanup)
}

func TestSourceFetchRequiresFetcher(t *testing.T) {
	source := Source{URL: "https://example.com/vex.json"}

	doc, cleanup, err := source.Fetch(context.Background(), nil)

	require.Error(t, err)
	assert.Empty(t, doc.Path)
	assert.NotNil(t, cleanup)
}
