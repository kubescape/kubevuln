package metrics

import (
	"context"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// RecordSBOMImport deliberately excludes image, repository, signer and raw errors
// from labels. Invalid outcomes collapse to one bounded series.
func RecordSBOMImport(ctx context.Context, result string, bytes int64) {
	switch result {
	case "disabled", "reference", "policy", "resolution", "discovery", "verification", "compatibility", "accepted":
	default:
		result = "other"
	}
	recorderMu.RLock()
	counter, byteCounter := sbomImportCounter, sbomImportBytes
	recorderMu.RUnlock()
	if counter != nil {
		counter.Add(ctx, 1, metric.WithAttributes(attribute.String("result", result)))
	}
	if byteCounter != nil && bytes > 0 {
		byteCounter.Add(ctx, bytes)
	}
}
