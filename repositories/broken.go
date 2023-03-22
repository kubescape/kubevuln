package repositories

import (
	"context"
	"errors"

	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/kubevuln/core/ports"
	"go.opentelemetry.io/otel"
)

type BrokenStore struct{}

var _ ports.CVERepository = (*BrokenStore)(nil)

var _ ports.SBOMRepository = (*BrokenStore)(nil)

func NewBrokenStorage() *BrokenStore {
	return &BrokenStore{}
}

func (b BrokenStore) GetSBOM(ctx context.Context, _ string, _ string) (sbom domain.SBOM, err error) {
	_, span := otel.Tracer("").Start(ctx, "BrokenStore.GetSBOM")
	defer span.End()
	return domain.SBOM{}, errors.New("expected error")
}

func (b BrokenStore) GetSBOMp(ctx context.Context, _ string, _ string) (sbom domain.SBOM, err error) {
	_, span := otel.Tracer("").Start(ctx, "BrokenStore.GetSBOMp")
	defer span.End()
	return domain.SBOM{}, errors.New("expected error")
}

func (b BrokenStore) StoreSBOM(ctx context.Context, _ domain.SBOM) error {
	_, span := otel.Tracer("").Start(ctx, "BrokenStore.StoreSBOM")
	defer span.End()
	return errors.New("expected error")
}

func (b BrokenStore) GetCVE(ctx context.Context, _ string, _ string, _ string, _ string) (cve domain.CVEManifest, err error) {
	_, span := otel.Tracer("").Start(ctx, "BrokenStore.GetCVE")
	defer span.End()
	return domain.CVEManifest{}, errors.New("expected error")
}

func (b BrokenStore) StoreCVE(ctx context.Context, cve domain.CVEManifest, withRelevancy bool) error {
	_, span := otel.Tracer("").Start(ctx, "BrokenStore.StoreCVE")
	defer span.End()
	return errors.New("expected error")
}
