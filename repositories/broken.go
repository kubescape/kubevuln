package repositories

import (
	"context"

	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/kubevuln/core/ports"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"go.opentelemetry.io/otel"
)

type BrokenStore struct{}

var _ ports.ContainerProfileRepository = (*BrokenStore)(nil)

var _ ports.CVERepository = (*BrokenStore)(nil)

var _ ports.SBOMRepository = (*BrokenStore)(nil)

func NewBrokenStorage() *BrokenStore {
	return &BrokenStore{}
}

func (b BrokenStore) GetContainerProfile(ctx context.Context, _ string, _ string) (v1beta1.ContainerProfile, error) {
	_, span := otel.Tracer("").Start(ctx, "BrokenStore.GetContainerProfile")
	defer span.End()
	return v1beta1.ContainerProfile{}, domain.ErrExpectedError
}

func (b BrokenStore) GetSBOM(ctx context.Context, _ string, _ string) (domain.SBOM, error) {
	_, span := otel.Tracer("").Start(ctx, "BrokenStore.GetSBOM")
	defer span.End()
	return domain.SBOM{}, domain.ErrExpectedError
}

func (b BrokenStore) GetCVESummary(ctx context.Context) (*v1beta1.VulnerabilityManifestSummary, error) {
	_, span := otel.Tracer("").Start(ctx, "BrokenStore.GetCVESummary")
	defer span.End()
	return &v1beta1.VulnerabilityManifestSummary{}, nil
}

func (b BrokenStore) StoreSBOM(ctx context.Context, _ domain.SBOM, _ bool) error {
	_, span := otel.Tracer("").Start(ctx, "BrokenStore.StoreSBOM")
	defer span.End()
	return domain.ErrExpectedError
}

func (b BrokenStore) GetCVE(ctx context.Context, _ string, _ string, _ string, _ string) (domain.CVEManifest, error) {
	_, span := otel.Tracer("").Start(ctx, "BrokenStore.GetCVE")
	defer span.End()
	return domain.CVEManifest{}, domain.ErrExpectedError
}

func (b BrokenStore) StoreCVE(ctx context.Context, _ domain.CVEManifest, _ bool) error {
	_, span := otel.Tracer("").Start(ctx, "BrokenStore.StoreCVE")
	defer span.End()
	return domain.ErrExpectedError
}

func (b BrokenStore) StoreCVESummary(ctx context.Context, _ domain.CVEManifest, _ domain.CVEManifest, _ bool) error {
	_, span := otel.Tracer("").Start(ctx, "BrokenStore.StoreCVESummary")
	defer span.End()
	return domain.ErrExpectedError
}

func (b BrokenStore) StoreVEX(ctx context.Context, _ domain.CVEManifest, _ domain.CVEManifest, _ bool) error {
	_, span := otel.Tracer("").Start(ctx, "BrokenStore.StoreVEX")
	defer span.End()
	return domain.ErrExpectedError
}
