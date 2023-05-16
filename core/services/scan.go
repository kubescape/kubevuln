package services

import (
	"context"
	"errors"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/instanceidhandler/v1"
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
	workload, ok := ctx.Value(domain.WorkloadKey{}).(domain.ScanCommand)
	if !ok {
		return errors.New("no workload found in context")
	}

	// check if SBOM is already available
	sbom := domain.SBOM{}
	var err error
	if s.storage {
		sbom, err = s.sbomRepository.GetSBOM(ctx, workload.ImageHash, s.sbomCreator.Version())
		if err != nil {
			logger.L().Ctx(ctx).Warning("error getting SBOM", helpers.Error(err), helpers.String("imageID", workload.ImageHash))
		}
	}

	// if SBOM is not available, create it
	if sbom.Content == nil {
		// create SBOM
		sbom, err = s.sbomCreator.CreateSBOM(ctx, workload.ImageHash, optionsFromWorkload(workload))
		if err != nil {
			return err
		}
	}

	// store SBOM
	if s.storage {
		err = s.sbomRepository.StoreSBOM(ctx, sbom)
		if err != nil {
			return err
		}
	}

	return nil
}

// Ready proxies the cveScanner's readiness
func (s *ScanService) Ready(ctx context.Context) bool {
	return s.cveScanner.Ready(ctx)
}

// ScanCVE implements the "Scanning for CVEs flow"
func (s *ScanService) ScanCVE(ctx context.Context) error {
	ctx, span := otel.Tracer("").Start(ctx, "ScanService.ScanCVE")
	defer span.End()

	// retrieve workload from context
	workload, ok := ctx.Value(domain.WorkloadKey{}).(domain.ScanCommand)
	if !ok {
		return errors.New("no workload found in context")
	}
	logger.L().Info("scan started", helpers.String("imageID", workload.ImageHash), helpers.String("jobID", workload.JobID))

	// report to platform
	err := s.platform.SendStatus(ctx, domain.Started)
	if err != nil {
		logger.L().Ctx(ctx).Warning("telemetry error", helpers.Error(err), helpers.String("imageID", workload.ImageHash))
	}

	// check if CVE manifest is already available
	cve := domain.CVEManifest{}
	if s.storage {
		cve, err = s.cveRepository.GetCVE(ctx, workload.ImageHash, s.sbomCreator.Version(), s.cveScanner.Version(ctx), s.cveScanner.DBVersion(ctx))
		if err != nil {
			logger.L().Ctx(ctx).Warning("error getting CVE", helpers.Error(err), helpers.String("imageID", workload.ImageHash))
		}
	}

	// if CVE manifest is not available, create it
	if cve.Content == nil {
		// check if SBOM is already available
		sbom := domain.SBOM{}
		if s.storage {
			sbom, err = s.sbomRepository.GetSBOM(ctx, workload.ImageHash, s.sbomCreator.Version())
			if err != nil {
				logger.L().Ctx(ctx).Warning("error getting SBOM", helpers.Error(err), helpers.String("imageID", workload.ImageHash))
			}
		}

		// if SBOM is not available, create it
		if sbom.Content == nil {
			// create SBOM
			sbom, err = s.sbomCreator.CreateSBOM(ctx, workload.ImageHash, optionsFromWorkload(workload))
			if err != nil {
				return err
			}
			// store SBOM
			if s.storage {
				err = s.sbomRepository.StoreSBOM(ctx, sbom)
				if err != nil {
					logger.L().Ctx(ctx).Warning("error storing SBOM", helpers.Error(err), helpers.String("imageID", workload.ImageHash))
				}
			}
		}

		// do not process timed out SBOM
		if sbom.Status == instanceidhandler.Incomplete {
			return errors.New("SBOM incomplete due to timeout, skipping CVE scan")
		}

		// scan for CVE
		cve, err = s.cveScanner.ScanSBOM(ctx, sbom)
		if err != nil {
			return err
		}

		// store CVE
		if s.storage {
			err = s.cveRepository.StoreCVE(ctx, cve, false)
			if err != nil {
				logger.L().Ctx(ctx).Warning("error storing CVE", helpers.Error(err), helpers.String("imageID", workload.ImageHash))
			}
		}
	}

	// check if SBOM' is already available
	sbomp := domain.SBOM{}
	if s.storage && workload.InstanceID != "" {
		sbomp, err = s.sbomRepository.GetSBOMp(ctx, workload.InstanceID, s.sbomCreator.Version())
		if err != nil {
			logger.L().Ctx(ctx).Warning("error getting relevant SBOM", helpers.Error(err), helpers.String("instanceID", workload.InstanceID))
		}
	}

	// with SBOM' we can scan for CVE'
	cvep := domain.CVEManifest{}
	if sbomp.Content != nil {
		// scan for CVE'
		cvep, err = s.cveScanner.ScanSBOM(ctx, sbomp)
		if err != nil {
			return err
		}
		// store CVE'
		if s.storage {
			cvep.Wlid = workload.Wlid
			err = s.cveRepository.StoreCVE(ctx, cvep, true)
			if err != nil {
				logger.L().Ctx(ctx).Warning("error storing CVEp", helpers.Error(err), helpers.String("instanceID", workload.InstanceID))
			}
		}
	}

	// report scan success to platform
	err = s.platform.SendStatus(ctx, domain.Success)
	if err != nil {
		logger.L().Ctx(ctx).Warning("telemetry error", helpers.Error(err), helpers.String("imageID", workload.ImageHash))
	}
	// submit CVE manifest to platform
	err = s.platform.SubmitCVE(ctx, cve, cvep)
	if err != nil {
		return err
	}
	// report submit success to platform
	err = s.platform.SendStatus(ctx, domain.Done)
	if err != nil {
		logger.L().Ctx(ctx).Warning("telemetry error", helpers.Error(err), helpers.String("imageID", workload.ImageHash))
	}

	logger.L().Info("scan complete", helpers.String("imageID", workload.ImageHash), helpers.String("jobID", workload.JobID))
	return nil
}

func (s *ScanService) ScanRegistry(ctx context.Context) error {
	ctx, span := otel.Tracer("").Start(ctx, "ScanService.ScanRegistry")
	defer span.End()

	// retrieve workload from context
	workload, ok := ctx.Value(domain.WorkloadKey{}).(domain.ScanCommand)
	if !ok {
		return errors.New("no workload found in context")
	}
	logger.L().Info("registry scan started", helpers.String("imageID", workload.ImageTag), helpers.String("jobID", workload.JobID))

	// report to platform
	err := s.platform.SendStatus(ctx, domain.Started)
	if err != nil {
		logger.L().Ctx(ctx).Warning("telemetry error", helpers.Error(err), helpers.String("imageID", workload.ImageTag))
	}

	// create SBOM
	sbom, err := s.sbomCreator.CreateSBOM(ctx, workload.ImageTag, optionsFromWorkload(workload))
	if err != nil {
		return err
	}

	// do not process timed out SBOM
	if sbom.Status == instanceidhandler.Incomplete {
		return errors.New("SBOM incomplete due to timeout, skipping CVE scan")
	}

	// scan for CVE
	cve, err := s.cveScanner.ScanSBOM(ctx, sbom)
	if err != nil {
		return err
	}

	// report scan success to platform
	err = s.platform.SendStatus(ctx, domain.Success)
	if err != nil {
		logger.L().Ctx(ctx).Warning("telemetry error", helpers.Error(err), helpers.String("imageID", workload.ImageTag))
	}
	// submit CVE manifest to platform
	err = s.platform.SubmitCVE(ctx, cve, domain.CVEManifest{})
	if err != nil {
		return err
	}
	// report submit success to platform
	err = s.platform.SendStatus(ctx, domain.Done)
	if err != nil {
		logger.L().Ctx(ctx).Warning("telemetry error", helpers.Error(err), helpers.String("imageID", workload.ImageTag))
	}

	logger.L().Info("registry scan complete", helpers.String("imageID", workload.ImageTag), helpers.String("jobID", workload.JobID))
	return nil
}

func enrichContext(ctx context.Context, workload domain.ScanCommand) context.Context {
	// record start time
	ctx = context.WithValue(ctx, domain.TimestampKey{}, time.Now().Unix())
	// generate unique scanID and add to context
	scanID := generateScanID(workload)

	ctx = context.WithValue(ctx, domain.ScanIDKey{}, scanID)
	// add workload to context
	ctx = context.WithValue(ctx, domain.WorkloadKey{}, workload)
	return ctx
}

func generateScanID(workload domain.ScanCommand) string {
	if workload.InstanceID != "" {
		return workload.InstanceID
	}
	if workload.ImageTag != "" && workload.ImageHash != "" {
		return workload.ImageTag + workload.ImageHash
	}
	return uuid.New().String()
}

func optionsFromWorkload(workload domain.ScanCommand) domain.RegistryOptions {
	options := domain.RegistryOptions{}
	for _, cred := range workload.Credentialslist {
		if cred.Auth != "" {
			options.Credentials = append(options.Credentials, domain.RegistryCredentials{Authority: cred.Auth})
		}
		if cred.RegistryToken != "" {
			options.Credentials = append(options.Credentials, domain.RegistryCredentials{Token: cred.RegistryToken})
		}
		if cred.Username != "" && cred.Password != "" {
			options.Credentials = append(options.Credentials, domain.RegistryCredentials{Username: cred.Username, Password: cred.Password})
		}
	}
	if useHTTP, ok := workload.Args[domain.AttributeUseHTTP]; ok {
		options.InsecureUseHTTP = useHTTP.(bool)
	}
	if skipTLSVerify, ok := workload.Args[domain.AttributeSkipTLSVerify]; ok {
		options.InsecureSkipTLSVerify = skipTLSVerify.(bool)
	}
	return options
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
		parentSpan.SetAttributes(attribute.String("version", os.Getenv("RELEASE")))
		ctx = trace.ContextWithSpan(ctx, parentSpan)
	}
	return ctx, nil
}

func (s *ScanService) ValidateScanCVE(ctx context.Context, workload domain.ScanCommand) (context.Context, error) {
	_, span := otel.Tracer("").Start(ctx, "ScanService.ValidateScanCVE")
	defer span.End()

	ctx = enrichContext(ctx, workload)
	// validate inputs
	if workload.ImageHash == "" {
		return ctx, errors.New("missing imageID")
	}
	// add instanceID and imageID to parent span
	if parentSpan := trace.SpanFromContext(ctx); parentSpan != nil {
		if workload.InstanceID != "" {
			parentSpan.SetAttributes(attribute.String("instanceID", workload.InstanceID))
		}
		parentSpan.SetAttributes(attribute.String("imageID", workload.ImageHash))
		parentSpan.SetAttributes(attribute.String("version", os.Getenv("RELEASE")))
		parentSpan.SetAttributes(attribute.String("wlid", workload.Wlid))
		ctx = trace.ContextWithSpan(ctx, parentSpan)
	}
	// report to platform
	err := s.platform.SendStatus(ctx, domain.Accepted)
	if err != nil {
		logger.L().Ctx(ctx).Error("telemetry error", helpers.Error(err))
	}
	return ctx, nil
}

func (s *ScanService) ValidateScanRegistry(ctx context.Context, workload domain.ScanCommand) (context.Context, error) {
	_, span := otel.Tracer("").Start(ctx, "ScanService.ValidateScanRegistry")
	defer span.End()

	ctx = enrichContext(ctx, workload)
	// validate inputs
	if workload.ImageTag == "" {
		return ctx, errors.New("missing imageID")
	}
	// add imageID to parent span
	if parentSpan := trace.SpanFromContext(ctx); parentSpan != nil {
		parentSpan.SetAttributes(attribute.String("imageID", workload.ImageTag))
		parentSpan.SetAttributes(attribute.String("version", os.Getenv("RELEASE")))
		ctx = trace.ContextWithSpan(ctx, parentSpan)
	}
	return ctx, nil
}
