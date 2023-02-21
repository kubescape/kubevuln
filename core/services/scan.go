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

// ScanService implements ScanService from ports, this is the business component
// business logic should be independent of implementations
type ScanService struct {
	sbomCreator    ports.SBOMCreator
	sbomRepository ports.SBOMRepository
	cveScanner     ports.CVEScanner
	cveRepository  ports.CVERepository
	platform       ports.Platform
}

var _ ports.ScanService = (*ScanService)(nil)

// NewScanService initializes the ScanService with all injected dependencies
func NewScanService(sbomCreator ports.SBOMCreator, sbomRepository ports.SBOMRepository, cveScanner ports.CVEScanner, cveRepository ports.CVERepository, platform ports.Platform) *ScanService {
	return &ScanService{
		sbomCreator:    sbomCreator,
		sbomRepository: sbomRepository,
		cveScanner:     cveScanner,
		cveRepository:  cveRepository,
		platform:       platform,
	}
}

// GenerateSBOM implements the "Generate SBOM flow"
func (s *ScanService) GenerateSBOM(ctx context.Context, imageID string, workload domain.ScanCommand) error {
	ctx, span := otel.Tracer("").Start(ctx, "GenerateSBOM")
	defer span.End()
	// check if SBOM is already available
	sbom, err := s.sbomRepository.GetSBOM(ctx, imageID, s.sbomCreator.Version())
	if err != nil {
		return err
	}
	if sbom.Content != nil {
		// this is not supposed to happen, problem with Operator?
		logger.L().Ctx(ctx).Warning("SBOM already generated", helpers.String("imageID", imageID))
		return nil
	}
	// create SBOM
	sbom, err = s.sbomCreator.CreateSBOM(ctx, imageID, domain.RegistryOptions{})
	if err != nil {
		return err
	}
	// TODO add telemetry to Platform
	return s.sbomRepository.StoreSBOM(ctx, sbom)
}

// Ready proxies the cveScanner's readiness
func (s *ScanService) Ready() bool {
	return s.cveScanner.Ready()
}

// ScanCVE implements the "Scanning for CVEs flow"
func (s *ScanService) ScanCVE(ctx context.Context, instanceID string, imageID string, workload domain.ScanCommand) error {
	ctx, span := otel.Tracer("").Start(ctx, "ScanCVE")
	defer span.End()
	// report to platform
	err := s.platform.SendStatus(workload, domain.Started)
	if err != nil {
		logger.L().Ctx(ctx).Error("telemetry error", helpers.Error(err))
	}
	// check if CVE scans are already available
	cve, err := s.cveRepository.GetCVE(ctx, imageID, s.sbomCreator.Version(), s.cveScanner.Version(), s.cveScanner.DBVersion())
	if err != nil {
		return err
	}
	if cve.Content == nil {
		// need to scan for CVE
		// check if SBOM is available
		sbom, err := s.sbomRepository.GetSBOM(ctx, imageID, s.sbomCreator.Version())
		if err != nil {
			return err
		}
		if sbom.Content == nil {
			// this is not supposed to happen, problem with Operator?
			txt := "missing SBOM"
			logger.L().Ctx(ctx).Error(txt, helpers.String("imageID", imageID), helpers.String("SBOMCreatorVersion", s.sbomCreator.Version()))
			return errors.New(txt) // TODO do proper error reporting https://go.dev/blog/go1.13-errors
		}
		// scan for CVE
		cve, err = s.cveScanner.ScanSBOM(ctx, sbom)
		if err != nil {
			return err
		}
	}
	// check if SBOM' is available
	sbomp, err := s.sbomRepository.GetSBOMp(ctx, instanceID, s.sbomCreator.Version())
	if err != nil {
		return err
	}
	if sbomp.Content != nil {
		// scan for CVE'
		cvep, err := s.cveScanner.ScanSBOM(ctx, sbomp)
		if err != nil {
			return err
		}
		// merge CVE and CVE' to create relevant CVE
		cve, err = s.cveScanner.CreateRelevantCVE(ctx, cve, cvep)
		if err != nil {
			return err
		}
	}
	// report to platform
	err = s.platform.SendStatus(workload, domain.Success)
	if err != nil {
		logger.L().Ctx(ctx).Error("telemetry error", helpers.Error(err))
	}
	// submit to storage
	err = s.cveRepository.StoreCVE(ctx, cve)
	if err != nil {
		return err
	}
	// TODO add submit to Platform
	// report to platform
	err = s.platform.SendStatus(workload, domain.Done)
	if err != nil {
		logger.L().Ctx(ctx).Error("telemetry error", helpers.Error(err))
	}
	return nil
}

func (s *ScanService) ValidateGenerateSBOM(ctx context.Context, imageID string, workload domain.ScanCommand) error {
	// validate inputs
	if imageID == "" {
		return errors.New("missing imageID")
	}
	return nil
}

func (s *ScanService) ValidateScanCVE(ctx context.Context, instanceID string, imageID string, workload domain.ScanCommand) error {
	// validate inputs
	if instanceID == "" {
		return errors.New("missing instanceID")
	}
	if imageID == "" {
		return errors.New("missing imageID")
	}
	// report to platform
	err := s.platform.SendStatus(workload, domain.Accepted)
	if err != nil {
		logger.L().Ctx(ctx).Error("telemetry error", helpers.Error(err))
	}
	return nil
}
