package telemetry

import (
	"context"
	"net/http"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// InjectHTTP adds only W3C trace context, never baggage or payload attributes.
func InjectHTTP(r *http.Request) {
	otel.GetTextMapPropagator().Inject(r.Context(), propagation.HeaderCarrier(r.Header))
}

type metadataCarrier metadata.MD

func (m metadataCarrier) Get(k string) string {
	v := metadata.MD(m).Get(k)
	if len(v) > 0 {
		return v[0]
	}
	return ""
}
func (m metadataCarrier) Set(k, v string) { metadata.MD(m).Set(k, v) }
func (m metadataCarrier) Keys() []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// UnaryClientContext and UnaryServerContext propagate context without per-RPC spans.
func UnaryClientContext(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoke grpc.UnaryInvoker, opts ...grpc.CallOption) error {
	md, _ := metadata.FromOutgoingContext(ctx)
	md = md.Copy()
	otel.GetTextMapPropagator().Inject(ctx, metadataCarrier(md))
	return invoke(metadata.NewOutgoingContext(ctx, md), method, req, reply, cc, opts...)
}
func UnaryServerContext(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	return handler(otel.GetTextMapPropagator().Extract(ctx, metadataCarrier(md)), req)
}
