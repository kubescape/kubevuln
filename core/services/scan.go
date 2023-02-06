package services

import (
	"context"
	"errors"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/kubevuln/core/ports"
	"go.opentelemetry.io/otel"
)

type ScanService struct {
	sbomCreator    ports.SBOMCreator
	sbomRepository ports.SBOMRepository
	cveScanner     ports.CVEScanner
	cveRepository  ports.CVERepository
	armoPlatform   ports.Platform
}

var _ ports.ScanService = (*ScanService)(nil)

func NewScanService(sbomCreator ports.SBOMCreator, sbomRepository ports.SBOMRepository, cveScanner ports.CVEScanner, cveRepository ports.CVERepository, armoPlatform ports.Platform) *ScanService {
	return &ScanService{
		sbomCreator:    sbomCreator,
		sbomRepository: sbomRepository,
		cveScanner:     cveScanner,
		cveRepository:  cveRepository,
		armoPlatform:   armoPlatform,
	}
}

func (s *ScanService) GenerateSBOM(ctx context.Context, imageID string, workload domain.Workload) error {
	ctx, span := otel.Tracer("").Start(ctx, "GenerateSBOM")
	defer span.End()
	if imageID == "" {
		return errors.New("missing imageID")
	}
	sbom, err := s.sbomRepository.GetSBOM(ctx, imageID, s.sbomCreator.Version())
	if err != nil {
		return err
	}
	if sbom.Content != nil {
		logger.L().Ctx(ctx).Warning("SBOM already generated", helpers.String("imageID", imageID))
		return nil
	}
	sbom, err = s.sbomCreator.CreateSBOM(ctx, imageID, domain.RegistryOptions{})
	if err != nil {
		return err
	}
	// TODO add telemetry to Platform
	return s.sbomRepository.StoreSBOM(ctx, sbom)
}

func (s *ScanService) Ready() bool {
	return s.cveScanner.Ready()
}

func (s *ScanService) ScanCVE(ctx context.Context, instanceID string, imageID string, workload domain.Workload) error {
	ctx, span := otel.Tracer("").Start(ctx, "ScanCVE")
	defer span.End()
	if instanceID == "" {
		return errors.New("missing instanceID")
	}
	if imageID == "" {
		return errors.New("missing imageID")
	}
	cve, err := s.cveRepository.GetCVE(ctx, imageID, s.sbomCreator.Version(), s.cveScanner.Version(), s.cveScanner.DBVersion())
	if err != nil {
		return err
	}
	if cve.Content == nil {
		sbom, err := s.sbomRepository.GetSBOM(ctx, imageID, s.sbomCreator.Version())
		if err != nil {
			return err
		}
		if sbom.Content == nil {
			txt := "missing SBOM"
			logger.L().Ctx(ctx).Error(txt, helpers.String("imageID", imageID), helpers.String("SBOMCreatorVersion", s.sbomCreator.Version()))
			return errors.New(txt)
		}
		cve, err = s.cveScanner.ScanSBOM(ctx, sbom)
		if err != nil {
			return err
		}
	}
	sbomp, err := s.sbomRepository.GetSBOMp(ctx, imageID, s.sbomCreator.Version())
	if err != nil {
		return err
	}
	if sbomp.Content != nil {
		cvep, err := s.cveScanner.ScanSBOM(ctx, sbomp)
		if err != nil {
			return err
		}
		cve, err = s.cveScanner.CreateRelevantCVE(ctx, cve, cvep)
		if err != nil {
			return err
		}
	}
	// TODO add telemetry to Platform
	// TODO add submit to Platform
	return s.cveRepository.StoreCVE(ctx, cve)
}
