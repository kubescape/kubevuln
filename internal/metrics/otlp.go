package metrics

import (
	"context"
	"os"
	"strings"
	"time"

	"github.com/kubescape/go-logger/otelsetup"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
)

// OTLPReader attaches to the existing provider; it never creates another metric
// inventory. Configuration/auth matches shared setup where that API is compatible.
func OTLPReader(ctx context.Context, cfg otelsetup.ProviderConfig) (sdkmetric.Reader, error) {
	endpoint := os.Getenv("OTEL_EXPORTER_OTLP_METRICS_ENDPOINT")
	if endpoint == "" {
		endpoint = os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	}
	if endpoint == "" {
		return nil, nil
	}
	opts := []otlpmetricgrpc.Option{otlpmetricgrpc.WithTimeout(3 * time.Second), otlpmetricgrpc.WithRetry(otlpmetricgrpc.RetryConfig{Enabled: false})}
	if strings.Contains(endpoint, "://") {
		opts = append(opts, otlpmetricgrpc.WithEndpointURL(endpoint))
	} else {
		opts = append(opts, otlpmetricgrpc.WithEndpoint(endpoint))
	}
	if !strings.HasPrefix(endpoint, "https://") {
		opts = append(opts, otlpmetricgrpc.WithInsecure())
	}
	if cfg.AccessKey != "" {
		opts = append(opts, otlpmetricgrpc.WithHeaders(map[string]string{"X-API-KEY": cfg.AccessKey, "X-API-ACCOUNT": cfg.AccountID}))
	}
	exporter, err := otlpmetricgrpc.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return sdkmetric.NewPeriodicReader(exporter), nil
}

func ResourceAttributes(cfg otelsetup.ProviderConfig) []attribute.KeyValue {
	return []attribute.KeyValue{attribute.String("service.name", cfg.ServiceName), attribute.String("service.version", cfg.ServiceVersion), attribute.String("k8s.cluster.name", cfg.ClusterName), attribute.String("k8s.namespace.name", cfg.Namespace), attribute.String("k8s.pod.name", cfg.PodName), attribute.String("k8s.node.name", cfg.NodeName)}
}
