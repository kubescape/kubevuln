package services

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
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
func (s *ScanService) GenerateSBOM(ctx context.Context) error {
	ctx, span := otel.Tracer("").Start(ctx, "GenerateSBOM")
	defer span.End()
	// retrieve workload from context
	workload, ok := ctx.Value(domain.WorkloadKey).(domain.ScanCommand)
	if !ok {
		return errors.New("no workload found in context")
	}
	// check if SBOM is already available
	sbom, err := s.sbomRepository.GetSBOM(ctx, workload.ImageHash, s.sbomCreator.Version())
	if err != nil {
		return err
	}
	if sbom.Content != nil {
		// this is not supposed to happen, problem with Operator?
		logger.L().Ctx(ctx).Warning("SBOM already generated", helpers.String("imageID", workload.ImageHash))
		return nil
	}
	// create SBOM
	sbom, err = s.sbomCreator.CreateSBOM(ctx, workload.ImageHash, domain.RegistryOptions{})
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
func (s *ScanService) ScanCVE(ctx context.Context) error {
	ctx, span := otel.Tracer("").Start(ctx, "ScanCVE")
	defer span.End()
	// retrieve workload from context
	workload, ok := ctx.Value(domain.WorkloadKey).(domain.ScanCommand)
	if !ok {
		return errors.New("no workload found in context")
	}
	// report to platform
	err := s.platform.SendStatus(ctx, domain.Started)
	if err != nil {
		logger.L().Ctx(ctx).Error("telemetry error", helpers.Error(err))
	}
	// check storage statuses
	cveStorageOK := true
	sbomStorageOK := true
	// check if CVE scans are already available
	cve, err := s.cveRepository.GetCVE(ctx, workload.ImageHash, s.sbomCreator.Version(), s.cveScanner.Version(), s.cveScanner.DBVersion())
	if err != nil {
		cveStorageOK = false
		cve = domain.CVEManifest{}
	}
	if cve.Content == nil {
		// need to scan for CVE
		// check if SBOM is available
		sbom, err := s.sbomRepository.GetSBOM(ctx, workload.ImageHash, s.sbomCreator.Version())
		if err != nil {
			sbomStorageOK = false
			sbom = domain.SBOM{}
		}
		if sbom.Content == nil {
			if sbomStorageOK {
				// this is not supposed to happen, problem with Operator?
				txt := "missing SBOM"
				logger.L().Ctx(ctx).Error(txt, helpers.String("imageID", workload.ImageHash), helpers.String("SBOMCreatorVersion", s.sbomCreator.Version()))
				return errors.New(txt) // TODO do proper error reporting https://go.dev/blog/go1.13-errors
			} else {
				// create SBOM
				sbom, err = s.sbomCreator.CreateSBOM(ctx, workload.ImageHash, domain.RegistryOptions{})
				if err != nil {
					return err
				}
			}
		}
		// get exceptions
		exceptions, err := s.platform.GetCVEExceptions(ctx)
		if err != nil {
			return err
		}
		// scan for CVE
		cve, err = s.cveScanner.ScanSBOM(ctx, sbom, exceptions)
		if err != nil {
			return err
		}
	}
	// check if SBOM' is available
	hasRelevancy := false
	if sbomStorageOK {
		sbomp, err := s.sbomRepository.GetSBOMp(ctx, workload.Wlid, s.sbomCreator.Version())
		if err != nil {
			return err
		}
		if sbomp.Content != nil {
			hasRelevancy = true
			// scan for CVE'
			cvep, err := s.cveScanner.ScanSBOM(ctx, sbomp, nil)
			if err != nil {
				return err
			}
			// merge CVE and CVE' to create relevant CVE
			cve, err = s.cveScanner.CreateRelevantCVE(ctx, cve, cvep)
			if err != nil {
				return err
			}
		}
	}
	// report to platform
	err = s.platform.SendStatus(ctx, domain.Success)
	if err != nil {
		logger.L().Ctx(ctx).Error("telemetry error", helpers.Error(err))
	}
	// submit to storage
	if cveStorageOK {
		err = s.cveRepository.StoreCVE(ctx, cve)
		if err != nil {
			return err
		}
	}
	// submit to platform
	err = s.platform.SubmitCVE(ctx, cve, hasRelevancy)
	if err != nil {
		return err
	}
	// report to platform
	err = s.platform.SendStatus(ctx, domain.Done)
	if err != nil {
		logger.L().Ctx(ctx).Error("telemetry error", helpers.Error(err))
	}
	return nil
}

func (s *ScanService) ValidateGenerateSBOM(ctx context.Context, workload domain.ScanCommand) (context.Context, error) {
	// add workload to context
	ctx = context.WithValue(ctx, domain.WorkloadKey, workload)
	// validate inputs
	if workload.ImageHash == "" {
		return ctx, errors.New("missing imageID")
	}
	return ctx, nil
}

func (s *ScanService) ValidateScanCVE(ctx context.Context, workload domain.ScanCommand) (context.Context, error) {
	// record start time
	ctx = context.WithValue(ctx, domain.TimestampKey, time.Now().Unix())
	// generate unique scanID and add to context
	scanID, err := uuid.NewRandom()
	if err != nil {
		logger.L().Ctx(ctx).Error("error generating scanID", helpers.Error(err))
	}
	ctx = context.WithValue(ctx, domain.ScanIDKey, scanID.String())
	// add workload to context
	ctx = context.WithValue(ctx, domain.WorkloadKey, workload)
	// validate inputs
	if workload.Wlid == "" {
		return ctx, errors.New("missing instanceID")
	}
	if workload.ImageHash == "" {
		return ctx, errors.New("missing imageID")
	}
	// report to platform
	err = s.platform.SendStatus(ctx, domain.Accepted)
	if err != nil {
		logger.L().Ctx(ctx).Error("telemetry error", helpers.Error(err))
	}
	return ctx, nil
}
