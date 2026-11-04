package vexsource

import (
	"context"
	"errors"
	"fmt"

	"github.com/kubescape/kubevuln/internal/vexbatch"
)

// SourceFailure records an ingestion or staging failure for one configured
// source. A failure does not discard documents successfully ingested from
// other sources in the same batch.
type SourceFailure struct {
	URL string
	Err error
}

// Batch contains the staged documents and any sources that could not be
// ingested. Call Cleanup when the documents are no longer needed.
type Batch struct {
	Documents []vexbatch.Document
	Failures  []SourceFailure
	cleanups  []func()
}

// Err returns the failures as one error suitable for logging or reporting.
// Successfully staged documents remain available even when Err is non-nil.
func (b Batch) Err() error {
	failures := make([]error, 0, len(b.Failures))
	for _, failure := range b.Failures {
		failures = append(failures, fmt.Errorf("VEX source %q: %w", failure.URL, failure.Err))
	}
	return errors.Join(failures...)
}

// Cleanup removes every staged document file. It is safe to call more than
// once and should be deferred immediately after a successful IngestBatch.
func (b *Batch) Cleanup() {
	if b == nil {
		return
	}
	for _, cleanup := range b.cleanups {
		cleanup()
	}
	b.cleanups = nil
}

// IngestBatch fetches, validates, and stages each source independently.
// Unavailable or malformed sources are recorded in Failures while valid
// sources remain usable. This lets the scan orchestration layer report
// individual source failures without losing valid VEX documents from the
// same batch.
func (i Ingestor) IngestBatch(ctx context.Context, sources []Source) Batch {
	batch := Batch{
		Documents: make([]vexbatch.Document, 0, len(sources)),
		Failures:  make([]SourceFailure, 0),
		cleanups:  make([]func(), 0, len(sources)),
	}

	for _, source := range sources {
		document, err := i.Ingest(ctx, source)
		if err != nil {
			batch.Failures = append(batch.Failures, SourceFailure{
				URL: source.URL,
				Err: err,
			})
			continue
		}

		staged, cleanup, err := document.BatchDocument()
		if err != nil {
			batch.Failures = append(batch.Failures, SourceFailure{
				URL: document.URL,
				Err: err,
			})
			continue
		}

		batch.Documents = append(batch.Documents, staged)
		batch.cleanups = append(batch.cleanups, cleanup)
	}

	return batch
}
