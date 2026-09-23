package vexsource

import (
	"context"

	"github.com/kubescape/kubevuln/internal/safefetch"
)

// Ingestor fetches and validates external VEX sources.
type Ingestor struct {
	Fetcher *safefetch.Fetcher
}

// Ingest retrieves and validates a VEX document from the given source.
func (i Ingestor) Ingest(ctx context.Context, source Source) (Document, error) {
	return source.Fetch(ctx, i.Fetcher)
}
