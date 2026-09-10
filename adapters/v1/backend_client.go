package v1

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"time"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/armoapi-go/identifiers"
	"github.com/armosec/utils-go/httputils"
	backendClientV1 "github.com/kubescape/backend/pkg/client/v1"
)

// BackendClient defines the interface for interacting with upstream Kubescape/ARMO backend services.
type BackendClient interface {
	GetCVEExceptions(ctx context.Context, apiServerRestURL, accountID string, designator *identifiers.PortalDesignator, headers map[string]string) ([]armotypes.VulnerabilityExceptionPolicy, error)
	HttpPost(ctx context.Context, httpClient httputils.IHttpClient, fullURL string, headers map[string]string, body []byte, maxElapsedTime time.Duration) (*http.Response, error)
	SendStatus(sender *backendClientV1.BaseReportSender, status string, sendReport bool)
}

// defaultBackendClient is the production implementation of BackendClient delegating to kubescape/backend and HTTP endpoints.
type defaultBackendClient struct{}

func (c *defaultBackendClient) GetCVEExceptions(ctx context.Context, apiServerRestURL, accountID string, designator *identifiers.PortalDesignator, headers map[string]string) ([]armotypes.VulnerabilityExceptionPolicy, error) {
	return backendClientV1.GetCVEExceptionByDesignator(ctx, apiServerRestURL, accountID, designator, headers)
}

func (c *defaultBackendClient) HttpPost(ctx context.Context, httpClient httputils.IHttpClient, fullURL string, headers map[string]string, body []byte, maxElapsedTime time.Duration) (*http.Response, error) {
	return httpPostWithContext(ctx, httpClient, fullURL, headers, body, maxElapsedTime)
}

func (c *defaultBackendClient) SendStatus(sender *backendClientV1.BaseReportSender, status string, sendReport bool) {
	sender.SendStatus(status, sendReport)
}

// MockBackendClient provides a mockable implementation of BackendClient for testing.
type MockBackendClient struct {
	GetCVEExceptionsFunc func(ctx context.Context, apiServerRestURL, accountID string, designator *identifiers.PortalDesignator, headers map[string]string) ([]armotypes.VulnerabilityExceptionPolicy, error)
	HttpPostFunc         func(ctx context.Context, httpClient httputils.IHttpClient, fullURL string, headers map[string]string, body []byte, maxElapsedTime time.Duration) (*http.Response, error)
	SendStatusFunc       func(sender *backendClientV1.BaseReportSender, status string, sendReport bool)
}

var _ BackendClient = (*MockBackendClient)(nil)

func (m *MockBackendClient) GetCVEExceptions(ctx context.Context, apiServerRestURL, accountID string, designator *identifiers.PortalDesignator, headers map[string]string) ([]armotypes.VulnerabilityExceptionPolicy, error) {
	if m.GetCVEExceptionsFunc != nil {
		return m.GetCVEExceptionsFunc(ctx, apiServerRestURL, accountID, designator, headers)
	}
	return nil, nil
}

func (m *MockBackendClient) HttpPost(ctx context.Context, httpClient httputils.IHttpClient, fullURL string, headers map[string]string, body []byte, maxElapsedTime time.Duration) (*http.Response, error) {
	if m.HttpPostFunc != nil {
		return m.HttpPostFunc(ctx, httpClient, fullURL, headers, body, maxElapsedTime)
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewReader(nil)),
	}, nil
}

func (m *MockBackendClient) SendStatus(sender *backendClientV1.BaseReportSender, status string, sendReport bool) {
	if m.SendStatusFunc != nil {
		m.SendStatusFunc(sender, status, sendReport)
	}
}
