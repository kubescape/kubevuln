package services

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/kubescape/k8s-interface/instanceidhandler"
	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/k8s-interface/names"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/kubescape/storage/pkg/registry/file/dynamicpathdetector"

	"github.com/akyoto/cache"
	"github.com/armosec/armoapi-go/armotypes"
	"github.com/docker/docker/api/types/registry"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/google/uuid"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	v1 "github.com/kubescape/kubevuln/adapters/v1"
	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/kubevuln/core/ports"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

const (
	cleaningInterval = 1 * time.Minute
	ttl              = 10 * time.Minute
)

// ScanService implements ScanService from ports, this is the business component
// business logic should be independent of implementations
type ScanService struct {
	sbomCreator       ports.SBOMCreator
	sbomRepository    ports.SBOMRepository
	cveScanner        ports.CVEScanner
	cveRepository     ports.CVERepository
	platform          ports.Platform
	relevancyProvider ports.Relevancy
	sbomGeneration    bool
	storage           bool
	vexGeneration     bool
	tooManyRequests   *cache.Cache
}

var _ ports.ScanService = (*ScanService)(nil)

// NewScanService initializes the ScanService with all injected dependencies
func NewScanService(sbomCreator ports.SBOMCreator, sbomRepository ports.SBOMRepository, cveScanner ports.CVEScanner, cveRepository ports.CVERepository, platform ports.Platform, relevancyProvider ports.Relevancy, storage bool, vexGeneration bool, sbomGeneration bool) *ScanService {
	return &ScanService{
		sbomCreator:       sbomCreator,
		sbomRepository:    sbomRepository,
		cveScanner:        cveScanner,
		cveRepository:     cveRepository,
		platform:          platform,
		relevancyProvider: relevancyProvider,
		sbomGeneration:    sbomGeneration,
		storage:           storage,
		vexGeneration:     vexGeneration,
		tooManyRequests:   cache.New(cleaningInterval),
	}
}

func (s *ScanService) checkCreateSBOM(err error, key string) {
	if err != nil {
		var transportError *transport.Error
		if errors.As(err, &transportError) && transportError.StatusCode == http.StatusTooManyRequests {
			s.tooManyRequests.Set(key, true, ttl)
		}
	}
}

// GenerateSBOM implements the "Generate SBOM flow"
// FIXME check if we still use this method
func (s *ScanService) GenerateSBOM(ctx context.Context) error {
	ctx, span := otel.Tracer("").Start(ctx, "ScanService.GenerateSBOM")
	defer span.End()

	ctx = addTimestamp(ctx)

	// retrieve workload from context
	workload, ok := ctx.Value(domain.WorkloadKey{}).(domain.ScanCommand)
	if !ok {
		return domain.ErrCastingWorkload
	}

	// check if SBOM is already available
	sbom := domain.SBOM{}
	var err error
	if s.storage {
		sbom, err = s.sbomRepository.GetSBOM(ctx, workload.ImageSlug, s.sbomCreator.Version())
		if err != nil {
			logger.L().Ctx(ctx).Warning("error getting SBOM", helpers.Error(err),
				helpers.String("imageSlug", workload.ImageSlug))
		}
	}

	// if SBOM is not available, create it
	if sbom.Content == nil {
		// create SBOM
		sbom, err = s.sbomCreator.CreateSBOM(ctx, workload.ImageSlug, workload.ImageHash, workload.ImageTagNormalized, optionsFromWorkload(workload))
		s.checkCreateSBOM(err, workload.ImageHash)
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

func (s *ScanService) ScanAP(mainCtx context.Context) error {
	mainCtx, span := otel.Tracer("").Start(mainCtx, "ScanService.ScanAP")
	defer span.End()

	mainCtx = addTimestamp(mainCtx)

	// retrieve workload from context
	workload, ok := mainCtx.Value(domain.WorkloadKey{}).(domain.ScanCommand)
	if !ok {
		return domain.ErrCastingWorkload
	}
	name := workload.Args[domain.ArgsName].(string)
	namespace := workload.Args[domain.ArgsNamespace].(string)
	logger.L().Info("scan started",
		helpers.String("name", name),
		helpers.String("namespace", namespace),
		helpers.String("jobID", workload.JobID))

	scans, err := s.relevancyProvider.GetContainerRelevancyScans(mainCtx, namespace, name)
	if err != nil {
		return fmt.Errorf("error getting container relevancy scans: %w", err)
	}

	for _, scan := range scans {
		slug, err := names.ImageInfoToSlug(scan.ImageTag, scan.ImageID)
		if err != nil {
			logger.L().Ctx(mainCtx).Warning("error getting image slug", helpers.Error(err),
				helpers.String("imageTag", scan.ImageTag),
				helpers.String("imageID", scan.ImageID))
			continue // we need the slug
		}

		instanceIDSlug, _ := scan.InstanceID.GetSlug(false)

		// create a workload inside a new context
		ctx := enrichContext(mainCtx, domain.ScanCommand{
			JobID:              uuid.NewString(),
			ImageSlug:          slug,
			ContainerName:      scan.ContainerName,
			ImageHash:          v1.NormalizeImageID(scan.ImageID, scan.ImageTag),
			ImageTagNormalized: scan.ImageTag,
			InstanceID:         instanceIDSlug,
			Wlid:               scan.Wlid,
			ParentJobID:        workload.ParentJobID,
			Session:            workload.Session,
			Args:               workload.Args,
			CredentialsList:    workload.CredentialsList,
		}, s.sbomCreator.Version())

		// check if CVE manifest is already available
		cve := domain.CVEManifest{}
		if s.storage {
			cve, err = s.cveRepository.GetCVE(ctx, slug, s.sbomCreator.Version(), s.cveScanner.Version(ctx), s.cveScanner.DBVersion(ctx))
			if err != nil {
				logger.L().Ctx(ctx).Warning("error getting CVE", helpers.Error(err),
					helpers.String("imageSlug", slug))
				// no continue, we move on
			}
		}
		sbom := domain.SBOM{}

		// check if we need SBOM
		if cve.Content == nil || s.storage {
			// check if SBOM is already available
			if s.storage {
				sbom, err = s.sbomRepository.GetSBOM(ctx, slug, s.sbomCreator.Version())
				if err != nil {
					logger.L().Ctx(ctx).Warning("error getting SBOM", helpers.Error(err),
						helpers.String("imageSlug", slug))
					// no continue, we might create it
				}
			}

			// if SBOM is not available, create it
			if sbom.Content == nil {
				if s.sbomGeneration {
					// create SBOM
					sbom, err = s.sbomCreator.CreateSBOM(ctx, slug, scan.ImageID, scan.ImageTag, optionsFromWorkload(workload))
					s.checkCreateSBOM(err, scan.ImageID)
					if err != nil {
						logger.L().Ctx(ctx).Warning("error creating SBOM", helpers.Error(err),
							helpers.String("imageSlug", slug))
						continue // we need the SBOM
					}
					// store SBOM
					if s.storage {
						err = s.sbomRepository.StoreSBOM(ctx, sbom)
						if err != nil {
							logger.L().Ctx(ctx).Warning("error storing SBOM", helpers.Error(err),
								helpers.String("imageSlug", slug))
							// no continue, storing the SBOM is not critical
						}
					}
				} else {
					logger.L().Ctx(ctx).Warning("missing SBOM",
						helpers.String("imageSlug", slug))
					continue // we need the SBOM
				}
			}

			// check SBOM status
			if sbom.Status == helpersv1.Incomplete || sbom.Status == helpersv1.TooLarge {
				logger.L().Ctx(ctx).Warning("incomplete or too large SBOM",
					helpers.String("imageSlug", slug))
				continue // do not process this SBOM
			}
		}

		// if CVE manifest is not available, create it
		if cve.Content == nil {
			// scan for CVE
			cve, err = s.cveScanner.ScanSBOM(ctx, sbom)
			if err != nil {
				logger.L().Ctx(ctx).Warning("error scanning SBOM", helpers.Error(err),
					helpers.String("imageSlug", slug))
				continue // we need the CVE
			}

			// store CVE
			if s.storage {
				err = s.cveRepository.StoreCVE(ctx, cve, false)
				if err != nil {
					logger.L().Ctx(ctx).Warning("error storing CVE", helpers.Error(err),
						helpers.String("imageSlug", slug))
					// no continue, storing the CVE is not critical
				}
				err = s.cveRepository.StoreCVESummary(ctx, cve, domain.CVEManifest{}, false)
				if err != nil {
					logger.L().Ctx(ctx).Warning("error storing CVE summary", helpers.Error(err),
						helpers.String("imageSlug", slug))
					// no continue, storing the CVE summary is not critical
				}
			}
		} else {
			if s.storage {
				// store summary CVE if it does not exist
				if cveSumm, err := s.cveRepository.GetCVESummary(ctx); err != nil || cveSumm == nil {
					err = s.cveRepository.StoreCVESummary(ctx, cve, domain.CVEManifest{}, false)
					if err != nil {
						logger.L().Ctx(ctx).Warning("error storing CVE summary", helpers.Error(err),
							helpers.String("imageSlug", slug))
						// no continue, storing the CVE summary is not critical
					}
				}
			}
		}

		// generate SBOM' from SBOM and relevant files
		sbomp := domain.SBOM{}
		if s.storage {
			sbomp, err = filterSBOM(sbom, scan.InstanceID, scan.Wlid, scan.RelevantFiles, scan.Labels)
			if err != nil {
				logger.L().Ctx(ctx).Warning("error filtering SBOM", helpers.Error(err),
					helpers.String("instanceID", scan.InstanceID.GetStringFormatted()))
				continue // we need the SBOM'
			}
		}

		// with SBOM' we can scan for CVE'
		cvep := domain.CVEManifest{}
		if sbomp.Content != nil {
			// scan for CVE'
			cvep, err = s.cveScanner.ScanSBOM(ctx, sbomp)
			if err != nil {
				logger.L().Ctx(ctx).Warning("error scanning filtered SBOM", helpers.Error(err),
					helpers.String("instanceID", scan.InstanceID.GetStringFormatted()))
				continue // we need the CVE'
			}
			// store CVE'
			if s.storage {
				cvep.Wlid = scan.Wlid
				err = s.cveRepository.StoreCVE(ctx, cvep, true)
				if err != nil {
					logger.L().Ctx(ctx).Warning("error storing CVEp", helpers.Error(err),
						helpers.String("instanceID", scan.InstanceID.GetStringFormatted()))
					// no continue, storing the CVE' is not critical
				}
				err = s.cveRepository.StoreCVESummary(ctx, cve, cvep, true)
				if err != nil {
					logger.L().Ctx(ctx).Warning("error storing CVE summary", helpers.Error(err),
						helpers.String("imageSlug", slug))
					// no continue, storing the CVE summary is not critical
				}
				if s.vexGeneration {
					err = s.cveRepository.StoreVEX(ctx, cve, cvep, true)
					if err != nil {
						logger.L().Ctx(ctx).Warning("error storing VEX", helpers.Error(err),
							helpers.String("imageSlug", slug))
						// no continue, storing the VEX is not critical
					}
				}
			}
		}
		// submit CVE manifest to platform
		err = s.platform.SubmitCVE(ctx, cve, cvep)
		if err != nil {
			logger.L().Ctx(ctx).Warning("error submitting CVEs", helpers.Error(err),
				helpers.String("instanceID", scan.InstanceID.GetStringFormatted()))
			continue // we need to submit the CVE
		}
	}

	logger.L().Info("scan complete",
		helpers.String("name", name),
		helpers.String("namespace", namespace),
		helpers.String("jobID", workload.JobID))
	return nil
}

// ScanCVE implements the "Scanning for CVEs flow"
func (s *ScanService) ScanCVE(ctx context.Context) error {
	ctx, span := otel.Tracer("").Start(ctx, "ScanService.ScanCVE")
	defer span.End()

	ctx = addTimestamp(ctx)

	// retrieve workload from context
	workload, ok := ctx.Value(domain.WorkloadKey{}).(domain.ScanCommand)
	if !ok {
		return domain.ErrCastingWorkload
	}
	logger.L().Info("scan started",
		helpers.String("imageSlug", workload.ImageSlug),
		helpers.String("jobID", workload.JobID))

	// check if CVE manifest is already available
	var err error
	cve := domain.CVEManifest{}
	if s.storage {
		cve, err = s.cveRepository.GetCVE(ctx, workload.ImageSlug, s.sbomCreator.Version(), s.cveScanner.Version(ctx), s.cveScanner.DBVersion(ctx))
		if err != nil {
			logger.L().Ctx(ctx).Warning("error getting CVE", helpers.Error(err),
				helpers.String("imageSlug", workload.ImageSlug))
		}
	}

	sbom := domain.SBOM{}
	// check if we need SBOM
	if cve.Content == nil || (s.storage && workload.InstanceID != "") {
		// check if SBOM is already available
		if s.storage {
			sbom, err = s.sbomRepository.GetSBOM(ctx, workload.ImageSlug, s.sbomCreator.Version())
			if err != nil {
				logger.L().Ctx(ctx).Warning("error getting SBOM", helpers.Error(err),
					helpers.String("imageSlug", workload.ImageSlug))
			}
		}

		// if SBOM is not available, create it
		if sbom.Content == nil {
			if s.sbomGeneration {
				// create SBOM
				sbom, err = s.sbomCreator.CreateSBOM(ctx, workload.ImageSlug, workload.ImageHash, workload.ImageTag, optionsFromWorkload(workload))
				s.checkCreateSBOM(err, workload.ImageHash)
				if err != nil {
					return fmt.Errorf("error creating SBOM: %w", err)
				}
				// store SBOM
				if s.storage {
					err = s.sbomRepository.StoreSBOM(ctx, sbom)
					if err != nil {
						logger.L().Ctx(ctx).Warning("error storing SBOM", helpers.Error(err),
							helpers.String("imageSlug", workload.ImageSlug))
					}
				}
			} else {
				logger.L().Ctx(ctx).Warning("missing SBOM",
					helpers.String("imageSlug", workload.ImageSlug))
				return domain.ErrMissingSBOM
			}
		}

		// do not process timed out SBOM
		if sbom.Status == helpersv1.Incomplete || sbom.Status == helpersv1.TooLarge {
			return domain.ErrIncompleteSBOM
		}
	}

	// if CVE manifest is not available, create it
	if cve.Content == nil {
		// scan for CVE
		cve, err = s.cveScanner.ScanSBOM(ctx, sbom)
		if err != nil {
			return fmt.Errorf("error scanning SBOM: %w", err)
		}

		// store CVE
		if s.storage {
			err = s.cveRepository.StoreCVE(ctx, cve, false)
			if err != nil {
				logger.L().Ctx(ctx).Warning("error storing CVE", helpers.Error(err),
					helpers.String("imageSlug", workload.ImageSlug))
			}
			err = s.cveRepository.StoreCVESummary(ctx, cve, domain.CVEManifest{}, false)
			if err != nil {
				logger.L().Ctx(ctx).Warning("error storing CVE summary", helpers.Error(err),
					helpers.String("imageSlug", workload.ImageSlug))
			}
		}
	} else {
		if s.storage {
			// store summary CVE if does not exist
			if cveSumm, err := s.cveRepository.GetCVESummary(ctx); err != nil || cveSumm == nil {
				err = s.cveRepository.StoreCVESummary(ctx, cve, domain.CVEManifest{}, false)
				if err != nil {
					logger.L().Ctx(ctx).Warning("error storing CVE summary", helpers.Error(err),
						helpers.String("imageSlug", workload.ImageSlug))
				}
			}
		}
	}

	// submit CVE manifest to platform
	err = s.platform.SubmitCVE(ctx, cve, domain.CVEManifest{})
	if err != nil {
		return fmt.Errorf("error submitting CVEs: %w", err)
	}

	logger.L().Info("scan complete",
		helpers.String("imageSlug", workload.ImageSlug),
		helpers.String("instanceID", workload.InstanceID),
		helpers.String("jobID", workload.JobID))
	return nil
}

func (s *ScanService) ScanRegistry(ctx context.Context) error {
	ctx, span := otel.Tracer("").Start(ctx, "ScanService.ScanRegistry")
	defer span.End()

	ctx = addTimestamp(ctx)

	// retrieve workload from context
	workload, ok := ctx.Value(domain.WorkloadKey{}).(domain.ScanCommand)
	if !ok {
		return domain.ErrCastingWorkload
	}
	logger.L().Info("registry scan started",
		helpers.String("imageSlug", workload.ImageSlug),
		helpers.String("jobID", workload.JobID))

	// report to platform
	err := s.platform.SendStatus(ctx, domain.Started)
	if err != nil {
		logger.L().Ctx(ctx).Warning("telemetry error", helpers.Error(err),
			helpers.String("imageSlug", workload.ImageSlug))
	}

	// create SBOM
	sbom, err := s.sbomCreator.CreateSBOM(ctx, workload.ImageSlug, workload.ImageHash, workload.ImageTagNormalized, optionsFromWorkload(workload))
	s.checkCreateSBOM(err, workload.ImageTagNormalized)
	if err != nil {
		repErr := s.platform.ReportError(ctx, err)
		if repErr != nil {
			logger.L().Ctx(ctx).Warning("telemetry error", helpers.Error(repErr),
				helpers.String("imageSlug", workload.ImageSlug))
		}
		return err
	}

	// do not process timed out SBOM
	if sbom.Status == helpersv1.Incomplete || sbom.Status == helpersv1.TooLarge {
		return domain.ErrIncompleteSBOM
	}

	// scan for CVE
	cve, err := s.cveScanner.ScanSBOM(ctx, sbom)
	if err != nil {
		repErr := s.platform.ReportError(ctx, err)
		if repErr != nil {
			logger.L().Ctx(ctx).Warning("telemetry error", helpers.Error(repErr),
				helpers.String("imageSlug", workload.ImageSlug))
		}
		return err
	}

	// report scan success to platform
	err = s.platform.SendStatus(ctx, domain.Success)
	if err != nil {
		logger.L().Ctx(ctx).Warning("telemetry error", helpers.Error(err),
			helpers.String("imageSlug", workload.ImageSlug))
	}
	// submit CVE manifest to platform
	err = s.platform.SubmitCVE(ctx, cve, domain.CVEManifest{})
	if err != nil {
		return err
	}
	// report submit success to platform
	err = s.platform.SendStatus(ctx, domain.Done)
	if err != nil {
		logger.L().Ctx(ctx).Warning("telemetry error", helpers.Error(err),
			helpers.String("imageID", workload.ImageSlug))
	}

	logger.L().Info("registry scan complete",
		helpers.String("imageSlug", workload.ImageSlug),
		helpers.String("jobID", workload.JobID))
	return nil
}

func addTimestamp(ctx context.Context) context.Context {
	return context.WithValue(ctx, domain.TimestampKey{}, time.Now().Unix())
}

func enrichContext(ctx context.Context, workload domain.ScanCommand, scannerVersion string) context.Context {
	// generate unique scanID and add to context

	scanID := generateScanID(workload, scannerVersion)
	ctx = context.WithValue(ctx, domain.ScanIDKey{}, scanID)
	// add workload to context
	ctx = context.WithValue(ctx, domain.WorkloadKey{}, workload)
	return ctx
}

func generateScanID(workload domain.ScanCommand, scannerVersion string) string {

	scannerVersion = strings.ReplaceAll(scannerVersion, ".", "-")
	if workload.InstanceID != "" && armotypes.ValidateContainerScanID(workload.InstanceID) {
		if scannerVersion == "" {
			return workload.InstanceID
		}
		return fmt.Sprintf("%s-%s", workload.InstanceID, scannerVersion)
	}

	if workload.ImageTagNormalized != "" && workload.ImageHash != "" {
		sum := sha256.Sum256([]byte(workload.ImageTagNormalized + workload.ImageHash + scannerVersion))
		if scanID := fmt.Sprintf("%x", sum); armotypes.ValidateContainerScanID(scanID) {
			return scanID
		}
	}
	return uuid.New().String()
}

func optionsFromWorkload(workload domain.ScanCommand) domain.RegistryOptions {
	options := domain.RegistryOptions{}
	options.Credentials = registryCredentialsFromCredentialsList(workload.CredentialsList)

	if useHTTP, ok := workload.Args[domain.AttributeUseHTTP]; ok {
		options.InsecureUseHTTP = useHTTP.(bool)
	}
	if skipTLSVerify, ok := workload.Args[domain.AttributeSkipTLSVerify]; ok {
		options.InsecureSkipTLSVerify = skipTLSVerify.(bool)
	}

	logger.L().Debug("created registryOptions from workload",
		helpers.String("imageTagNormalized", workload.ImageTagNormalized),
		helpers.String("credentials", credentialsLog(options.Credentials)))
	return options
}

// credentialsLog returns a string representation of the credentials without the password and token
func credentialsLog(credentials []domain.RegistryCredentials) string {
	var sb strings.Builder
	for _, rc := range credentials {
		sb.WriteString(fmt.Sprintf("[Authority: %s, Username: %s, Password: *** (%d), Token: *** (%d)]", rc.Authority, rc.Username, len(rc.Password), len(rc.Token)))
	}

	return sb.String()
}

func registryCredentialsFromCredentialsList(credentials []registry.AuthConfig) []domain.RegistryCredentials {
	registryCredentials := make([]domain.RegistryCredentials, len(credentials))
	for i, cred := range credentials {
		rc := domain.RegistryCredentials{}
		if cred.ServerAddress != "" {
			rc.Authority = parseAuthorityFromServerAddress(cred.ServerAddress)
		}
		if cred.RegistryToken != "" {
			rc.Token = cred.RegistryToken
		}
		if cred.Username != "" && cred.Password != "" {
			rc.Username = cred.Username
			rc.Password = cred.Password
		}

		registryCredentials[i] = rc
	}
	return registryCredentials
}

func parseAuthorityFromServerAddress(serverAddress string) string {
	if serverAddress == "" {
		return ""
	}

	// server address has no scheme
	if !strings.HasPrefix(serverAddress, "http") {
		res, _, _ := strings.Cut(serverAddress, "/")
		return res
	}
	parsedURL, err := url.Parse(serverAddress)
	if err != nil || parsedURL.Host == "" {
		return serverAddress
	}

	return parsedURL.Host
}

func filterSBOM(sbom domain.SBOM, instanceID instanceidhandler.IInstanceID, wlid string, relevantFiles mapset.Set[string], labels map[string]string) (domain.SBOM, error) {
	name, err := instanceID.GetSlug(false)
	if err != nil {
		return domain.SBOM{}, fmt.Errorf("error getting slug from instance id: %w", err)
	}
	filteredSBOM := domain.SBOM{
		Name: name,
		Annotations: map[string]string{
			helpersv1.ImageIDMetadataKey:       sbom.Annotations[helpersv1.ImageIDMetadataKey],
			helpersv1.ImageTagMetadataKey:      sbom.Annotations[helpersv1.ImageTagMetadataKey],
			helpersv1.InstanceIDMetadataKey:    instanceID.GetStringFormatted(),
			helpersv1.StatusMetadataKey:        sbom.Annotations[helpersv1.StatusMetadataKey],
			helpersv1.WlidMetadataKey:          wlid,
			helpersv1.ContainerNameMetadataKey: labels[helpersv1.ContainerNameMetadataKey],
		},
		Labels:             labels,
		SBOMCreatorName:    sbom.SBOMCreatorName,
		SBOMCreatorVersion: sbom.SBOMCreatorVersion,
		Status:             sbom.Status,
		Content: &v1beta1.SyftDocument{
			SyftSource:     sbom.Content.SyftSource,
			Distro:         sbom.Content.Distro,
			SyftDescriptor: sbom.Content.SyftDescriptor,
			Schema:         sbom.Content.Schema,
		},
	}
	addedArtifactIDs := mapset.NewSet[string]()
	addedFileIDs := mapset.NewSet[string]()
	addedRelationshipIDs := mapset.NewSet[string]()

	// filter relevant files with dynamic paths
	var dynamicPaths []string
	relevantFiles.Each(func(file string) bool {
		if strings.Contains(file, dynamicpathdetector.DynamicIdentifier) {
			dynamicPaths = append(dynamicPaths, file)
		}
		return false
	})

	// filter relevant file list
	for _, f := range sbom.Content.Files {
		// the .location.realPath is not the ID of the file, that's why the map identifier is the ID and not the path
		if !addedFileIDs.Contains(f.ID) {
			// try direct match first
			if relevantFiles.Contains(f.Location.RealPath) {
				addedFileIDs.Add(f.ID)
				filteredSBOM.Content.Files = append(filteredSBOM.Content.Files, f)
				continue
			}
			// then try dynamic match (expensive lookup)
			for _, dynamicPath := range dynamicPaths {
				if dynamicpathdetector.CompareDynamic(dynamicPath, f.Location.RealPath) {
					addedFileIDs.Add(f.ID)
					filteredSBOM.Content.Files = append(filteredSBOM.Content.Files, f)
					break
				}
			}
		}
	}

	// filter relevant relationships. A relationship is relevant if the child is a relevant file
	relationshipsArtifacts := mapset.NewSet[string]()
	for _, relationship := range sbom.Content.ArtifactRelationships {
		if addedFileIDs.Contains(relationship.Child) && !addedRelationshipIDs.Contains(getRelationshipID(relationship)) { // if the child is a relevant file
			relationshipsArtifacts.Add(relationship.Parent)
			addedRelationshipIDs.Add(getRelationshipID(relationship))
			filteredSBOM.Content.ArtifactRelationships = append(filteredSBOM.Content.ArtifactRelationships, relationship)
		}
	}

	// Add children of relevant relationships (that the parent is not relevant)
	for _, relationship := range sbom.Content.ArtifactRelationships {
		if relationshipsArtifacts.Contains(relationship.Child) && !addedRelationshipIDs.Contains(getRelationshipID(relationship)) {
			relationshipsArtifacts.Add(relationship.Parent)
			addedRelationshipIDs.Add(getRelationshipID(relationship))
			filteredSBOM.Content.ArtifactRelationships = append(filteredSBOM.Content.ArtifactRelationships, relationship)
		}
	}

	// filter relevant artifacts. An artifact is relevant if it is in the relevant relationships
	for _, artifact := range sbom.Content.Artifacts {
		if relationshipsArtifacts.Contains(artifact.ID) && !addedArtifactIDs.Contains(artifact.ID) {
			addedArtifactIDs.Add(artifact.ID)
			filteredSBOM.Content.Artifacts = append(filteredSBOM.Content.Artifacts, artifact)
		}
	}

	return filteredSBOM, nil
}

func getRelationshipID(relationship v1beta1.SyftRelationship) string {
	return fmt.Sprintf("%s/%s/%s", relationship.Parent, relationship.Child, relationship.Type)
}

func (s *ScanService) ValidateGenerateSBOM(ctx context.Context, workload domain.ScanCommand) (context.Context, error) {
	_, span := otel.Tracer("").Start(ctx, "ScanService.ValidateGenerateSBOM")
	defer span.End()

	ctx = enrichContext(ctx, workload, s.sbomCreator.Version())
	// validate inputs
	if workload.ImageHash == "" || workload.ImageSlug == "" {
		return ctx, domain.ErrMissingImageInfo
	}
	// add imageSlug to parent span
	if parentSpan := trace.SpanFromContext(ctx); parentSpan != nil {
		parentSpan.SetAttributes(attribute.String("imageSlug", workload.ImageSlug))
		parentSpan.SetAttributes(attribute.String("version", os.Getenv("RELEASE")))
		ctx = trace.ContextWithSpan(ctx, parentSpan)
	}
	// check if previous image pull resulted in TOOMANYREQUESTS error
	if _, ok := s.tooManyRequests.Get(workload.ImageHash); ok {
		return ctx, domain.ErrTooManyRequests
	}
	return ctx, nil
}

func (s *ScanService) ValidateScanAP(ctx context.Context, workload domain.ScanCommand) (context.Context, error) {
	_, span := otel.Tracer("").Start(ctx, "ScanService.ValidateScanAP")
	defer span.End()
	ctx = enrichContext(ctx, workload, s.sbomCreator.Version())
	// validate inputs
	name := workload.Args[domain.ArgsName].(string)
	namespace := workload.Args[domain.ArgsNamespace].(string)
	if name == "" || namespace == "" {
		return ctx, domain.ErrMissingApInfo
	}
	// add instanceID and imageSlug to parent span
	if parentSpan := trace.SpanFromContext(ctx); parentSpan != nil {
		parentSpan.SetAttributes(attribute.String("name", name))
		parentSpan.SetAttributes(attribute.String("namespace", namespace))
		parentSpan.SetAttributes(attribute.String("version", os.Getenv("RELEASE")))
		parentSpan.SetAttributes(attribute.String("wlid", workload.Wlid))
		ctx = trace.ContextWithSpan(ctx, parentSpan)
	}
	return ctx, nil
}

func (s *ScanService) ValidateScanCVE(ctx context.Context, workload domain.ScanCommand) (context.Context, error) {
	_, span := otel.Tracer("").Start(ctx, "ScanService.ValidateScanCVE")
	defer span.End()

	ctx = enrichContext(ctx, workload, s.sbomCreator.Version())
	// validate inputs
	if workload.ImageHash == "" || workload.ImageSlug == "" {
		return ctx, domain.ErrMissingImageInfo
	}
	// add instanceID and imageSlug to parent span
	if parentSpan := trace.SpanFromContext(ctx); parentSpan != nil {
		if workload.InstanceID != "" {
			parentSpan.SetAttributes(attribute.String("instanceID", workload.InstanceID))
		}
		parentSpan.SetAttributes(attribute.String("imageSlug", workload.ImageSlug))
		parentSpan.SetAttributes(attribute.String("version", os.Getenv("RELEASE")))
		parentSpan.SetAttributes(attribute.String("wlid", workload.Wlid))
		ctx = trace.ContextWithSpan(ctx, parentSpan)
	}
	// check if previous image pull resulted in TOOMANYREQUESTS error
	if _, ok := s.tooManyRequests.Get(workload.ImageHash); ok {
		return ctx, domain.ErrTooManyRequests
	}
	return ctx, nil
}

func (s *ScanService) ValidateScanRegistry(ctx context.Context, workload domain.ScanCommand) (context.Context, error) {
	_, span := otel.Tracer("").Start(ctx, "ScanService.ValidateScanRegistry")
	defer span.End()

	ctx = enrichContext(ctx, workload, s.sbomCreator.Version())
	// validate inputs
	if workload.ImageTagNormalized == "" || workload.ImageSlug == "" {
		return ctx, domain.ErrMissingImageInfo
	}
	// add imageSlug to parent span
	if parentSpan := trace.SpanFromContext(ctx); parentSpan != nil {
		parentSpan.SetAttributes(attribute.String("imageSlug", workload.ImageSlug))
		parentSpan.SetAttributes(attribute.String("version", os.Getenv("RELEASE")))
		ctx = trace.ContextWithSpan(ctx, parentSpan)
	}
	// check if previous image pull resulted in TOOMANYREQUESTS error
	if _, ok := s.tooManyRequests.Get(workload.ImageTagNormalized); ok {
		return ctx, domain.ErrTooManyRequests
	}
	return ctx, nil
}
