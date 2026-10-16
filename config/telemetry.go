package config

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/kubescape/backend/pkg/servicediscovery/v3"
)

// DiscoverTelemetry uses the existing v3 protocol and API_URL, with a hard
// request deadline and no retries. It intentionally does not read the event URL.
func DiscoverTelemetry(ctx context.Context, apiURL string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if apiURL == "" {
		return "", nil
	}
	client, err := v3.NewServiceDiscoveryClientV3(apiURL)
	if err != nil {
		return "", err
	}
	services, err := loadBackendServicesFromAPI(client, &http.Client{Timeout: 3 * time.Second, Transport: contextTransport{ctx: ctx}})
	if err != nil {
		return "", err
	}
	return services.GetMetricsUrl(), nil
}

type contextTransport struct{ ctx context.Context }

func (t contextTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	response, err := http.DefaultTransport.RoundTrip(req.WithContext(t.ctx))
	if err != nil {
		return nil, err
	}
	body := response.Body
	defer func() { _ = body.Close() }()
	content, err := io.ReadAll(io.LimitReader(response.Body, 1024*1024+1))
	if err != nil {
		return nil, err
	}
	if len(content) > 1024*1024 {
		return nil, fmt.Errorf("service discovery response exceeds 1 MiB")
	}
	response.Body = io.NopCloser(bytes.NewReader(content))
	return response, nil
}
