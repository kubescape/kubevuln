package vexsource

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/kubescape/kubevuln/internal/safefetch"
	"github.com/kubescape/kubevuln/internal/vexbatch"
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
	require.Equal(t, vexbatch.FormatOpenVEX, document.Format)

	batch, cleanup, err := document.BatchDocument()
	require.NoError(t, err)
	defer cleanup()
	require.Equal(t, vexbatch.FormatOpenVEX, batch.Format)
	require.NotEmpty(t, batch.Path)
}

func TestSourceFetch_EmptyURL(t *testing.T) {
	source := Source{}

	_, err := source.Fetch(context.Background(), safefetch.New())

	require.EqualError(t, err, "vexsource: URL is empty")
	tests := []struct {
		name string
		url  string
	}{
		{name: "empty string", url: ""},
		{name: "whitespace only spaces", url: "   "},
		{name: "whitespace only tabs and newlines", url: " \t\n "},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			source := Source{URL: tt.url}
			_, err := source.Fetch(context.Background(), safefetch.New())
			require.EqualError(t, err, "vexsource: URL is empty")
		})
	}
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


func TestSourceFetch_CSAF(t *testing.T) {
	csafDocument, err := os.ReadFile("../csafresolve/testdata/redhat-cve-2024-3094.json")
	require.NoError(t, err)

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(csafDocument)
	}))
	defer server.Close()

	source := Source{URL: server.URL, Format: vexbatch.FormatCSAF}
	fetcher := &safefetch.Fetcher{Client: server.Client(), MaxBytes: 10 << 20}

	document, err := source.Fetch(context.Background(), fetcher)
	require.NoError(t, err)
	require.Equal(t, vexbatch.FormatCSAF, document.Format)

	batch, cleanup, err := document.BatchDocument()
	require.NoError(t, err)
	defer cleanup()
	require.Equal(t, vexbatch.FormatCSAF, batch.Format)
	require.NotEmpty(t, batch.Path)
}

func TestSourceFetch_UnsupportedFormat(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(validOpenVEX))
	}))
	defer server.Close()

	source := Source{URL: server.URL, Format: vexbatch.Format("xml")}
	fetcher := &safefetch.Fetcher{Client: server.Client(), MaxBytes: 1 << 20}

	_, err := source.Fetch(context.Background(), fetcher)
	require.EqualError(t, err, "vexsource: unsupported format \"xml\"")
}

func TestSourceFetch_InvalidCSAF(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("{\"document\":{\"category\":\"not-csaf\"}}"))
	}))
	defer server.Close()

	source := Source{URL: server.URL, Format: vexbatch.FormatCSAF}
	fetcher := &safefetch.Fetcher{Client: server.Client(), MaxBytes: 1 << 20}

	_, err := source.Fetch(context.Background(), fetcher)
	require.Error(t, err)
}


func TestSourceFetch_MalformedCSAFRevisionHistory(t *testing.T) {
	csafDocument := malformedCSAFDocument(t, func(envelope map[string]any) {
		document := envelope["document"].(map[string]any)
		tracking := document["tracking"].(map[string]any)
		tracking["revision_history"] = []any{nil}
	})
	assertMalformedCSAFRejected(t, csafDocument)
}

func TestSourceFetch_MalformedCSAFVulnerabilities(t *testing.T) {
	csafDocument := malformedCSAFDocument(t, func(envelope map[string]any) {
		envelope["vulnerabilities"] = []any{nil}
	})
	assertMalformedCSAFRejected(t, csafDocument)
}

func malformedCSAFDocument(t *testing.T, mutate func(map[string]any)) []byte {
	data, err := os.ReadFile("../csafresolve/testdata/redhat-cve-2024-3094.json")
	require.NoError(t, err)

	var envelope map[string]any
	require.NoError(t, json.Unmarshal(data, &envelope))

	mutate(envelope)

	data, err = json.Marshal(envelope)
	require.NoError(t, err)
	return data
}

func assertMalformedCSAFRejected(t *testing.T, csafDocument []byte) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(csafDocument)
	}))
	defer server.Close()

	source := Source{URL: server.URL, Format: vexbatch.FormatCSAF}
	fetcher := &safefetch.Fetcher{Client: server.Client(), MaxBytes: 10 << 20}

	var err error
	require.NotPanics(t, func() {
		_, err = source.Fetch(context.Background(), fetcher)
	})
	require.Error(t, err)
	require.True(t, strings.Contains(err.Error(), "invalid CSAF document"))
}
