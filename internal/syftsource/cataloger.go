package syftsource

import (
	"context"

	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

// SBOMCataloger abstracts creating an SBOM from a source.
type SBOMCataloger interface {
	CreateSBOM(ctx context.Context, src source.Source, cfg *syft.CreateSBOMConfig) (*sbom.SBOM, error)
}

// DefaultSBOMCataloger is the production implementation that calls syft.CreateSBOM.
type DefaultSBOMCataloger struct{}

var _ SBOMCataloger = DefaultSBOMCataloger{}

// CreateSBOM calls syft.CreateSBOM.
func (DefaultSBOMCataloger) CreateSBOM(ctx context.Context, src source.Source, cfg *syft.CreateSBOMConfig) (*sbom.SBOM, error) {
	return syft.CreateSBOM(ctx, src, cfg)
}

// SBOMCatalogerFunc adapts a function to the SBOMCataloger interface.
type SBOMCatalogerFunc func(ctx context.Context, src source.Source, cfg *syft.CreateSBOMConfig) (*sbom.SBOM, error)

var _ SBOMCataloger = SBOMCatalogerFunc(nil)

// CreateSBOM calls the underlying function.
func (f SBOMCatalogerFunc) CreateSBOM(ctx context.Context, src source.Source, cfg *syft.CreateSBOMConfig) (*sbom.SBOM, error) {
	return f(ctx, src, cfg)
}
