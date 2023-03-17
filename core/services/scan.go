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
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// ScanService implements ScanService from ports, this is the business component
// business logic should be independent of implementations
type ScanService struct {
	sbomCreator    ports.SBOMCreator
	sbomRepository ports.SBOMRepository
	cveScanner     ports.CVEScanner
	cveRepository  ports.CVERepository
	platform       ports.Platform
	storage        bool
}

var _ ports.ScanService = (*ScanService)(nil)

// NewScanService initializes the ScanService with all injected dependencies
func NewScanService(sbomCreator ports.SBOMCreator, sbomRepository ports.SBOMRepository, cveScanner ports.CVEScanner, cveRepository ports.CVERepository, platform ports.Platform, storage bool) *ScanService {
	return &ScanService{
		sbomCreator:    sbomCreator,
		sbomRepository: sbomRepository,
		cveScanner:     cveScanner,
		cveRepository:  cveRepository,
		platform:       platform,
		storage:        storage,
	}
}

// GenerateSBOM implements the "Generate SBOM flow"
func (s *ScanService) GenerateSBOM(ctx context.Context) error {
	ctx, span := otel.Tracer("").Start(ctx, "ScanService.GenerateSBOM")
	defer span.End()
	// retrieve workload from context
	workload, ok := ctx.Value(domain.WorkloadKey).(domain.ScanCommand)
	if !ok {
		return errors.New("no workload found in context")
	}

	sbom := domain.SBOM{}
	var err error
	if s.storage {
		// check if SBOM is already available
		sbom, err = s.sbomRepository.GetSBOM(ctx, workload.ImageHash, s.sbomCreator.Version(ctx))
		if err != nil {
			logger.L().Ctx(ctx).Warning("error getting SBOM", helpers.Error(err), helpers.String("imageID", workload.ImageHash))
		}
	}
	if sbom.Content == nil {
		// create SBOM
		sbom, err = s.sbomCreator.CreateSBOM(ctx, workload.ImageHash, domain.RegistryOptions{})
		if err != nil {
			return err
		}
	}

	if s.storage {
		// store SBOM
		err = s.sbomRepository.StoreSBOM(ctx, sbom)
		if err != nil {
			return err
		}
		return nil
	} else {
		// here we need to scan for CVE (phase 1)
		// do not process timed out SBOM
		if sbom.Status == domain.SBOMStatusTimedOut {
			return errors.New("SBOM incomplete due to timeout, skipping CVE scan")
		}
		// scan for CVE
		cve, err := s.cveScanner.ScanSBOM(ctx, sbom)
		if err != nil {
			return err
		}
		// report to platform
		err = s.platform.SendStatus(ctx, domain.Success)
		if err != nil {
			logger.L().Ctx(ctx).Warning("telemetry error", helpers.Error(err), helpers.String("imageID", workload.ImageHash))
		}
		// submit to platform
		err = s.platform.SubmitCVE(ctx, cve, domain.CVEManifest{})
		if err != nil {
			return err
		}
		// report to platform
		err = s.platform.SendStatus(ctx, domain.Done)
		if err != nil {
			logger.L().Ctx(ctx).Warning("telemetry error", helpers.Error(err), helpers.String("imageID", workload.ImageHash))
		}
	}

	return nil
}

// Ready proxies the cveScanner's readiness
func (s *ScanService) Ready(ctx context.Context) bool {
	ctx, span := otel.Tracer("").Start(ctx, "ScanService.Ready")
	defer span.End()
	return s.cveScanner.Ready(ctx)
}

// ScanCVE implements the "Scanning for CVEs flow"
func (s *ScanService) ScanCVE(ctx context.Context) error {
	ctx, span := otel.Tracer("").Start(ctx, "ScanService.ScanCVE")
	defer span.End()
	// retrieve workload from context
	workload, ok := ctx.Value(domain.WorkloadKey).(domain.ScanCommand)
	if !ok {
		return errors.New("no workload found in context")
	}
	// report to platform
	err := s.platform.SendStatus(ctx, domain.Started)
	if err != nil {
		logger.L().Ctx(ctx).Warning("telemetry error", helpers.Error(err), helpers.String("imageID", workload.ImageHash))
	}

	// check if CVE scans are already available
	cve, err := s.cveRepository.GetCVE(ctx, workload.ImageHash, s.sbomCreator.Version(ctx), s.cveScanner.Version(ctx), s.cveScanner.DBVersion(ctx))
	if err != nil {
		logger.L().Ctx(ctx).Warning("error getting CVE", helpers.Error(err), helpers.String("imageID", workload.ImageHash))
	}
	if cve.Content == nil {
		// need to scan for CVE
		// check if SBOM is available
		sbom, err := s.sbomRepository.GetSBOM(ctx, workload.ImageHash, s.sbomCreator.Version(ctx))
		if err != nil {
			logger.L().Ctx(ctx).Warning("error getting SBOM", helpers.Error(err), helpers.String("imageID", workload.ImageHash))
		}
		if sbom.Content == nil {
			return errors.New("missing SBOM, skipping CVE scan")
		}
		// do not process timed out SBOM
		if sbom.Status == domain.SBOMStatusTimedOut {
			return errors.New("SBOM incomplete due to timeout, skipping CVE scan")
		}
		// scan for CVE
		cve, err = s.cveScanner.ScanSBOM(ctx, sbom)
		if err != nil {
			return err
		}
		// submit to storage
		err = s.cveRepository.StoreCVE(ctx, cve, false)
		if err != nil {
			return err
		}
	}
	// check if SBOM' is available
	cvep := domain.CVEManifest{}
	sbomp, err := s.sbomRepository.GetSBOMp(ctx, workload.Wlid, s.sbomCreator.Version(ctx))
	if err != nil {
		logger.L().Ctx(ctx).Warning("error getting SBOMp", helpers.Error(err), helpers.String("wlid", workload.Wlid))
	}
	if sbomp.Content != nil {
		// scan for CVE'
		cvep, err = s.cveScanner.ScanSBOM(ctx, sbomp)
		if err != nil {
			return err
		}
		// submit to storage
		err = s.cveRepository.StoreCVE(ctx, cvep, true)
		if err != nil {
			return err
		}
	}
	// report to platform
	err = s.platform.SendStatus(ctx, domain.Success)
	if err != nil {
		logger.L().Ctx(ctx).Warning("telemetry error", helpers.Error(err), helpers.String("imageID", workload.ImageHash))
	}
	// submit to platform
	err = s.platform.SubmitCVE(ctx, cve, cvep)
	if err != nil {
		return err
	}
	// report to platform
	err = s.platform.SendStatus(ctx, domain.Done)
	if err != nil {
		logger.L().Ctx(ctx).Warning("telemetry error", helpers.Error(err), helpers.String("imageID", workload.ImageHash))
	}
	return nil
}

func enrichContext(ctx context.Context, workload domain.ScanCommand) context.Context {
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
	return ctx
}

func (s *ScanService) ValidateGenerateSBOM(ctx context.Context, workload domain.ScanCommand) (context.Context, error) {
	_, span := otel.Tracer("").Start(ctx, "ScanService.ValidateGenerateSBOM")
	defer span.End()

	ctx = enrichContext(ctx, workload)
	// validate inputs
	if workload.ImageHash == "" {
		return ctx, errors.New("missing imageID")
	}
	// add imageID to parent span
	if parentSpan := trace.SpanFromContext(ctx); parentSpan != nil {
		parentSpan.SetAttributes(attribute.String("imageID", workload.ImageHash))
		ctx = trace.ContextWithSpan(ctx, parentSpan)
	}
	return ctx, nil
}

func (s *ScanService) ValidateScanCVE(ctx context.Context, workload domain.ScanCommand) (context.Context, error) {
	_, span := otel.Tracer("").Start(ctx, "ScanService.ValidateScanCVE")
	defer span.End()

	ctx = enrichContext(ctx, workload)
	// validate inputs
	if workload.Wlid == "" {
		return ctx, errors.New("missing instanceID")
	}
	if workload.ImageHash == "" {
		return ctx, errors.New("missing imageID")
	}
	// add instanceID and imageID to parent span
	if parentSpan := trace.SpanFromContext(ctx); parentSpan != nil {
		parentSpan.SetAttributes(attribute.String("instanceID", workload.Wlid))
		parentSpan.SetAttributes(attribute.String("imageID", workload.ImageHash))
		ctx = trace.ContextWithSpan(ctx, parentSpan)
	}
	// report to platform
	err := s.platform.SendStatus(ctx, domain.Accepted)
	if err != nil {
		logger.L().Ctx(ctx).Error("telemetry error", helpers.Error(err))
	}
	return ctx, nil
}
