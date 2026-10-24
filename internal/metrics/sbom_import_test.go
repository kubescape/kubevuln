package metrics

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSBOMImportMetricsBoundCardinality(t *testing.T) {
	m, err := New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = m.Shutdown(context.Background()) })
	RecordSBOMImport(context.Background(), "accepted", 1234)
	RecordSBOMImport(context.Background(), "registry.example/private:secret", -1)
	body := scrape(t, m)
	require.Contains(t, body, `kubevuln_sbom_import_attempts_total{result="accepted"} 1`)
	require.Contains(t, body, `kubevuln_sbom_import_attempts_total{result="other"} 1`)
	require.Contains(t, body, `kubevuln_sbom_import_bytes_total 1234`)
	require.NotContains(t, body, "registry.example")
}
