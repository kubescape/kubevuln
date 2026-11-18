package metrics

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRecordExternalVEXSource_NormalizesFormat pins the format label to the same three
// values whatever spelling the caller passes: an empty format is OpenVEX, as it is for the
// source itself, and anything unrecognized collapses to "other" so the label stays bounded.
func TestRecordExternalVEXSource_NormalizesFormat(t *testing.T) {
	m, err := New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = m.Shutdown(context.Background()) })

	ctx := context.Background()
	RecordExternalVEXSource(ctx, "", true)
	RecordExternalVEXSource(ctx, " OpenVEX ", true)
	RecordExternalVEXSource(ctx, "csaf", false)
	RecordExternalVEXSource(ctx, "\tCSAF\n", true)
	RecordExternalVEXSource(ctx, "https://vex.example.com/feed.json?token=secret", false)

	body := scrape(t, m)
	assert.Contains(t, body, `kubevuln_external_vex_sources_total{format="openvex",result="ingested"} 2`)
	assert.Contains(t, body, `kubevuln_external_vex_sources_total{format="csaf",result="ingested"} 1`)
	assert.Contains(t, body, `kubevuln_external_vex_sources_total{format="csaf",result="failed"} 1`)
	assert.Contains(t, body, `kubevuln_external_vex_sources_total{format="other",result="failed"} 1`)
	assert.NotContains(t, body, "vex.example.com")
}

func TestRecordExternalVEXScan_OutcomesAreDistinct(t *testing.T) {
	m, err := New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = m.Shutdown(context.Background()) })

	ctx := context.Background()
	RecordExternalVEXScan(ctx, ExternalVEXScanApplied)
	RecordExternalVEXScan(ctx, ExternalVEXScanApplied)
	RecordExternalVEXScan(ctx, ExternalVEXScanNoDocuments)
	RecordExternalVEXScan(ctx, ExternalVEXScanApplyFailed)
	RecordExternalVEXScan(ctx, ExternalVEXScanUnsupported)

	body := scrape(t, m)
	assert.Contains(t, body, `kubevuln_external_vex_scans_total{outcome="applied"} 2`)
	assert.Contains(t, body, `kubevuln_external_vex_scans_total{outcome="no_documents"} 1`)
	assert.Contains(t, body, `kubevuln_external_vex_scans_total{outcome="apply_failed"} 1`)
	assert.Contains(t, body, `kubevuln_external_vex_scans_total{outcome="unsupported"} 1`)
}

func TestRecordExternalVEX_BeforeNewIsANoOp(t *testing.T) {
	recorderMu.Lock()
	prevSource, prevScan := externalVEXSourceCounter, externalVEXScanCounter
	externalVEXSourceCounter, externalVEXScanCounter = nil, nil
	recorderMu.Unlock()
	defer func() {
		recorderMu.Lock()
		externalVEXSourceCounter, externalVEXScanCounter = prevSource, prevScan
		recorderMu.Unlock()
	}()

	assert.NotPanics(t, func() {
		RecordExternalVEXSource(context.Background(), ExternalVEXFormatCSAF, false)
		RecordExternalVEXScan(context.Background(), ExternalVEXScanApplied)
	})
}
