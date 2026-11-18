package metrics

import (
	"context"
	"strings"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

const (
	ExternalVEXFormatOpenVEX = "openvex"
	ExternalVEXFormatCSAF    = "csaf"
	ExternalVEXFormatOther   = "other"

	ExternalVEXSourceIngested = "ingested"
	ExternalVEXSourceFailed   = "failed"

	// ExternalVEXScanApplied means Grype evaluated the SBOM with at least one ingested
	// document. It says the documents were applied, not that any statement matched.
	ExternalVEXScanApplied = "applied"
	// ExternalVEXScanNoDocuments means every configured source failed, so the SBOM was
	// evaluated without external VEX.
	ExternalVEXScanNoDocuments = "no_documents"
	// ExternalVEXScanApplyFailed means Grype could not apply the ingested documents, so the
	// SBOM was evaluated again without external VEX.
	ExternalVEXScanApplyFailed = "apply_failed"
	// ExternalVEXScanUnsupported means the configured CVE scanner cannot apply VEX
	// documents, so the SBOM was evaluated without external VEX.
	ExternalVEXScanUnsupported = "unsupported"
)

// RecordExternalVEXSource reports whether one configured external VEX source was fetched,
// validated and staged (ExternalVEXSourceIngested) or not (ExternalVEXSourceFailed). The
// source URL is deliberately not a label: it is unbounded and can carry a token in its
// query string. format is normalized the way the source itself is, with an empty format
// meaning OpenVEX and anything unrecognized collapsing to ExternalVEXFormatOther.
func RecordExternalVEXSource(ctx context.Context, format string, ingested bool) {
	recorderMu.RLock()
	counter := externalVEXSourceCounter
	recorderMu.RUnlock()
	if counter == nil {
		return
	}
	switch format = strings.ToLower(strings.TrimSpace(format)); format {
	case "":
		format = ExternalVEXFormatOpenVEX
	case ExternalVEXFormatOpenVEX, ExternalVEXFormatCSAF:
	default:
		format = ExternalVEXFormatOther
	}
	result := ExternalVEXSourceFailed
	if ingested {
		result = ExternalVEXSourceIngested
	}
	counter.Add(ctx, 1, metric.WithAttributes(
		attribute.String("format", format),
		attribute.String("result", result),
	))
}

// RecordExternalVEXScan reports how external VEX was used for one SBOM evaluation made
// while external sources are configured (ExternalVEXScanApplied/ExternalVEXScanNoDocuments/
// ExternalVEXScanApplyFailed/ExternalVEXScanUnsupported). Every outcome other than
// ExternalVEXScanApplied means the findings were produced without external VEX.
func RecordExternalVEXScan(ctx context.Context, outcome string) {
	recorderMu.RLock()
	counter := externalVEXScanCounter
	recorderMu.RUnlock()
	if counter == nil {
		return
	}
	counter.Add(ctx, 1, metric.WithAttributes(
		attribute.String("outcome", outcome),
	))
}
