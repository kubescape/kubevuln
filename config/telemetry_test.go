package config

import (
	"context"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestDiscoverTelemetry(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		code       int
		want       string
		failed     bool
	}{
		{"metrics", `{"version":"v3","response":{"metrics":"collector.test:443","otel-events":"ignored"}}`, 200, "collector.test:443", false},
		{"missing", `{"version":"v3","response":{}}`, 200, "", false},
		{"failure", ``, 503, "", true},
		{"malformed", `{`, 200, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				require.Contains(t, r.URL.Path, "servicediscovery")
				w.WriteHeader(tc.code)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer s.Close()
			got, err := DiscoverTelemetry(context.Background(), s.URL)
			require.Equal(t, tc.failed, err != nil)
			require.Equal(t, tc.want, got)
			require.Equal(t, 1, calls)
		})
	}
}
func TestDiscoverTelemetryCancellation(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer s.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := DiscoverTelemetry(ctx, s.URL)
	require.Error(t, err)
	require.Less(t, time.Since(start), time.Second)
}

type telemetryTransportFunc func(*http.Request) (*http.Response, error)

func (f telemetryTransportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestDiscoverTelemetryNoAPIURL(t *testing.T) {
	original := http.DefaultTransport
	defer func() { http.DefaultTransport = original }()
	http.DefaultTransport = telemetryTransportFunc(func(*http.Request) (*http.Response, error) {
		t.Error("unconfigured discovery must not make HTTP requests or use a cloud fallback")
		return nil, context.Canceled
	})
	got, err := DiscoverTelemetry(context.Background(), "")
	require.NoError(t, err)
	require.Empty(t, got)
}

func TestDiscoverTelemetryBoundsResponse(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(make([]byte, 1024*1024+1)) }))
	defer s.Close()
	_, err := DiscoverTelemetry(context.Background(), s.URL)
	require.Error(t, err)
}

func TestDiscoverTelemetryMalformedURL(t *testing.T) {
	_, err := DiscoverTelemetry(context.Background(), "http://%")
	require.Error(t, err)
}
