package sbomreuse

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTransportBoundsChunkedResponses(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		_, _ = io.WriteString(w, "123456789")
	}))
	defer s.Close()
	tr := &boundedTransport{base: http.DefaultTransport, maxBody: 8, remaining: 100}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, s.URL, nil)
	require.NoError(t, err)
	err = roundTripError(tr, req)
	require.ErrorContains(t, err, "size budget")
	require.Equal(t, int64(9), tr.fetchedBytes())
}

func TestTransportRejectsPaginationAndCancellation(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Link", "</next>; rel=next")
		w.WriteHeader(200)
	}))
	defer s.Close()
	tr := &boundedTransport{base: http.DefaultTransport, maxBody: 100, remaining: 100}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, s.URL, nil)
	require.NoError(t, err)
	err = roundTripError(tr, req)
	require.ErrorContains(t, err, "paginated")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err = roundTripError(tr, req.WithContext(ctx))
	require.ErrorIs(t, err, context.Canceled)
}

func TestTransportTotalBudget(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "12345") }))
	defer s.Close()
	tr := &boundedTransport{base: http.DefaultTransport, maxBody: 10, remaining: 8}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, s.URL, nil)
	require.NoError(t, err)
	resp, err := tr.RoundTrip(req)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	err = roundTripError(tr, req)
	require.ErrorContains(t, err, "size budget")
}

func TestTransportRejectsLegacyDiscoveryAndRequestLimit(t *testing.T) {
	tr := &boundedTransport{base: http.DefaultTransport, maxBody: 100, remaining: 100, requests: 64}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://registry.example/v2/app/manifests/sha256-deadbeef", nil)
	require.NoError(t, err)
	err = roundTripError(tr, req)
	require.ErrorContains(t, err, "OCI referrers")
	req.URL.Path = "/v2/"
	err = roundTripError(tr, req)
	require.ErrorContains(t, err, "request budget")
}

// Close an unexpected successful response before asserting the expected error.
func roundTripError(tr http.RoundTripper, req *http.Request) error {
	resp, err := tr.RoundTrip(req)
	if resp != nil {
		_ = resp.Body.Close()
	}
	return err
}

type partialErrorBody struct {
	err    error
	closed bool
}

func (b *partialErrorBody) Read(p []byte) (int, error) { return copy(p, "partial"), b.err }
func (b *partialErrorBody) Close() error               { b.closed = true; return nil }

type responseTransport func(*http.Request) (*http.Response, error)

func (f responseTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestTransportCountsPartialReadErrors(t *testing.T) {
	for _, readErr := range []error{io.ErrUnexpectedEOF, context.DeadlineExceeded} {
		t.Run(readErr.Error(), func(t *testing.T) {
			body := &partialErrorBody{err: readErr}
			tr := &boundedTransport{base: responseTransport(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: body, ContentLength: -1}, nil
			}), maxBody: 100, remaining: 5}
			req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://registry.example/v2/", nil)
			require.NoError(t, err)
			require.ErrorIs(t, roundTripError(tr, req), readErr, "preserve the read error even when it exhausts the budget")
			require.Equal(t, int64(7), tr.fetchedBytes())
			require.Equal(t, int64(-2), tr.remaining)
			require.True(t, body.closed)
			require.ErrorContains(t, roundTripError(tr, req), "request budget")
		})
	}
}
