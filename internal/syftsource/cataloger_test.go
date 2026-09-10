package syftsource

import (
	"context"
	"testing"

	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
	"github.com/stretchr/testify/assert"
)

func TestSBOMCatalogerFunc(t *testing.T) {
	called := false
	fn := SBOMCatalogerFunc(func(ctx context.Context, src source.Source, cfg *syft.CreateSBOMConfig) (*sbom.SBOM, error) {
		called = true
		return &sbom.SBOM{}, nil
	})

	res, err := fn.CreateSBOM(context.Background(), nil, nil)
	assert.NoError(t, err)
	assert.NotNil(t, res)
	assert.True(t, called)
}
