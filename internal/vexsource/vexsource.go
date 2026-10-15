package vexsource

import (
	"context"
	"fmt"
	"strings"

	"github.com/kubescape/kubevuln/internal/safefetch"
	"github.com/kubescape/kubevuln/internal/vexbatch"
	"github.com/kubescape/kubevuln/internal/vexdoc"
	"github.com/kubescape/kubevuln/internal/vexvalidate"
)

// Source describes an external VEX document source.
type Source struct {
	URL    string
	Format vexbatch.Format
}

// Document is a validated VEX document fetched from an external source.
type Document struct {
	URL    string
	Data   []byte
	Format vexbatch.Format
}

// BatchDocument stages the validated document for Grype and returns a cleanup
// function that removes the temporary file. OpenVEX remains the default for
// callers that constructed Source before format selection was introduced.
func (d Document) BatchDocument() (vexbatch.Document, func(), error) {
	format := d.Format
	if format == "" {
		format = vexbatch.FormatOpenVEX
	}

	path, cleanup, err := vexdoc.WriteToTempFile(d.Data)
	if err != nil {
		return vexbatch.Document{}, func() {}, err
	}

	return vexbatch.Document{Format: format, Path: path}, cleanup, nil
}

// Fetch retrieves and validates the VEX document from the source.
func (s Source) Fetch(ctx context.Context, fetcher *safefetch.Fetcher) (Document, error) {
	s.URL = strings.TrimSpace(s.URL)
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

	format := s.Format
	if format == "" {
		format = vexbatch.FormatOpenVEX
	}

	switch format {
	case vexbatch.FormatOpenVEX:
		if err := vexvalidate.Validate(data); err != nil {
			return Document{}, fmt.Errorf("validating OpenVEX source: %w", err)
		}
	case vexbatch.FormatCSAF:
		if err := vexvalidate.ValidateCSAF(data); err != nil {
			return Document{}, fmt.Errorf("validating CSAF source: %w", err)
		}
	default:
		return Document{}, fmt.Errorf("vexsource: unsupported format %q", format)
	}

	return Document{
		URL:    s.URL,
		Data:   data,
		Format: format,
	}, nil
}
