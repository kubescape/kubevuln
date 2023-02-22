package repositories

import (
	"context"
	"errors"

	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/kubevuln/core/ports"
)

type BrokenStore struct{}

var _ ports.CVERepository = (*BrokenStore)(nil)

var _ ports.SBOMRepository = (*BrokenStore)(nil)

func (b BrokenStore) GetSBOM(context.Context, string, string) (sbom domain.SBOM, err error) {
	return domain.SBOM{}, errors.New("expected error")
}

func (b BrokenStore) GetSBOMp(context.Context, string, string) (sbom domain.SBOM, err error) {
	return domain.SBOM{}, errors.New("expected error")
}

func (b BrokenStore) StoreSBOM(context.Context, domain.SBOM) error {
	return errors.New("expected error")
}

func (b BrokenStore) GetCVE(context.Context, string, string, string, string) (cve domain.CVEManifest, err error) {
	return domain.CVEManifest{}, errors.New("expected error")
}

func (b BrokenStore) StoreCVE(context.Context, domain.CVEManifest) error {
	return errors.New("expected error")
}
