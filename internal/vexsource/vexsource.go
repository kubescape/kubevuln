package vexsource

import (
	"context"
	"fmt"

	"github.com/kubescape/kubevuln/internal/safefetch"
	"github.com/kubescape/kubevuln/internal/vexbatch"
	"github.com/kubescape/kubevuln/internal/vexdoc"
	"github.com/kubescape/kubevuln/internal/vexvalidate"
)

type Source struct {
	URL string
}

func (s Source) Fetch(ctx context.Context, fetcher *safefetch.Fetcher) (vexbatch.Document, func(), error) {
	if s.URL == "" {
		return vexbatch.Document{}, func() {}, fmt.Errorf("vexsource: URL is empty")
	}

	if fetcher == nil {
		return vexbatch.Document{}, func() {}, fmt.Errorf("vexsource: fetcher is nil")
	}

	data, err := fetcher.Fetch(ctx, s.URL)
	if err != nil {
		return vexbatch.Document{}, func() {}, fmt.Errorf("fetching VEX source: %w", err)
	}

	if err := vexvalidate.Validate(data); err != nil {
		return vexbatch.Document{}, func() {}, fmt.Errorf("validating VEX source: %w", err)
	}

	path, cleanup, err := vexdoc.WriteToTempFile(data)
	if err != nil {
		return vexbatch.Document{}, func() {}, fmt.Errorf("writing VEX source: %w", err)
	}

	return vexbatch.Document{
		Format: vexbatch.FormatOpenVEX,
		Path:   path,
	}, cleanup, nil
}
