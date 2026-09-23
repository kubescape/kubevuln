package vexsource

import (
	"context"
	"fmt"

	"github.com/kubescape/kubevuln/internal/safefetch"
	"github.com/kubescape/kubevuln/internal/vexvalidate"
)

// Source describes an external VEX document source.
type Source struct {
	URL string
}

// Document is a validated VEX document fetched from an external source.
type Document struct {
	URL  string
	Data []byte
}

// Fetch retrieves and validates the VEX document from the source.
func (s Source) Fetch(ctx context.Context, fetcher *safefetch.Fetcher) (Document, error) {
	if s.URL == "" {
		return Document{}, fmt.Errorf("vexsource: URL is empty")
	}

	if fetcher == nil {
		return Document{}, fmt.Errorf("vexsource: fetcher is nil")
	}

	data, err := fetcher.Fetch(ctx, s.URL)
	if err != nil {
		return Document{}, fmt.Errorf("fetching VEX source: %w", err)
	}

	if err := vexvalidate.Validate(data); err != nil {
		return Document{}, fmt.Errorf("validating VEX source: %w", err)
	}

	return Document{
		URL:  s.URL,
		Data: data,
	}, nil
}
