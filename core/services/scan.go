package services

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/akyoto/cache"
	"github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/armoapi-go/scanfailure"
	mapset "github.com/deckarep/golang-set/v2"
	"github.com/docker/docker/api/types/registry"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/google/uuid"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/instanceidhandler"
	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/k8s-interface/names"
	v1 "github.com/kubescape/kubevuln/adapters/v1"
	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/kubevuln/core/ports"
	"github.com/kubescape/kubevuln/internal/metrics"
	"github.com/kubescape/kubevuln/internal/tools"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/kubescape/storage/pkg/registry/file/dynamicpathdetector"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/sync/singleflight"
	"k8s.io/client-go/tools/record"
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
	partialRelevancy  bool
	platform          ports.Platform
	relevancyProvider ports.Relevancy
	sbomGeneration    bool
	storeFilteredSbom bool
	storage           bool
	vexGeneration     bool
	tooManyRequests   *cache.Cache
	metrics           *metrics.Metrics
	eventRecorder     record.EventRecorder
	sfGroup           singleflight.Group
}

// SetMetrics attaches an optional Metrics instance to the service. It is not
// a constructor parameter so existing callers (including the many test call
// sites) are unaffected; metric recording is a no-op until this is called.
func (s *ScanService) SetMetrics(m *metrics.Metrics) {
	s.metrics = m
}

// SetEventRecorder attaches an optional EventRecorder to the service. It is not a
// constructor parameter so existing callers (including the many test call sites) are
// unaffected; suppression events are a no-op (suppressions are still logged, just not
// recorded as K8s Events) until this is called.
func (s *ScanService) SetEventRecorder(r record.EventRecorder) {
	s.eventRecorder = r
}

var _ ports.ScanService = (*ScanService)(nil)

// NewScanService initializes the ScanService with all injected dependencies
func NewScanService(sbomCreator ports.SBOMCreator, sbomRepository ports.SBOMRepository, cveScanner ports.CVEScanner, cveRepository ports.CVERepository, platform ports.Platform, relevancyProvider ports.Relevancy, storage bool, vexGeneration bool, sbomGeneration bool, storeFilteredSbom bool, partialRelevancy bool) *ScanService {
	return &ScanService{
		cveRepository:     cveRepository,
		cveScanner:        cveScanner,
		partialRelevancy:  partialRelevancy,
		platform:          platform,
		relevancyProvider: relevancyProvider,
		sbomCreator:       sbomCreator,
		sbomGeneration:    sbomGeneration,
		sbomRepository:    sbomRepository,
		storage:           storage,
		storeFilteredSbom: storeFilteredSbom,
		tooManyRequests:   cache.New(cleaningInterval),
		vexGeneration:     vexGeneration,
	}
}

// rateLimitCacheKey returns the canonical key used to record and query registry rate-limit (429) backoffs.
// It uses workload.ImageTagNormalized along with a hash of any provided credentials.
// Including the credentials ensures that a 429 encountered by an unauthenticated pull
// does not cause a cross-tenant denial-of-service for workloads that use valid imagePullSecrets
// to bypass the rate limit. ImageHash is avoided because ScanRegistry payloads never populate it.
func rateLimitCacheKey(workload domain.ScanCommand) string {
	fingerprint := credentialsFingerprint(workload)
	if fingerprint == "" {
		return workload.ImageTagNormalized
	}
	return fmt.Sprintf("%s|%s", workload.ImageTagNormalized, fingerprint)
}

// credentialsFingerprint hashes the workload's credentials, so that keys built from it keep
// callers holding different credentials apart. Empty when the workload carries none.
func credentialsFingerprint(workload domain.ScanCommand) string {
	if len(workload.CredentialsList) == 0 {
		return ""
	}
	h := sha256.New()
	for _, cred := range workload.CredentialsList {
		// codeql[go/weak-crypto, go/weak-password-hashing]
		fmt.Fprintf(h, "%d:%s|%d:%s|%d:%s|%d:%s|%d:%s|%d:%s\n",
			len(cred.Username), cred.Username,
			len(cred.Password), cred.Password,
			len(cred.Auth), cred.Auth,
			len(cred.IdentityToken), cred.IdentityToken,
			len(cred.RegistryToken), cred.RegistryToken,
			len(cred.ServerAddress), cred.ServerAddress)
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

// sbomSingleflightKey identifies the SBOM a caller is about to produce, so concurrent
// callers only share work when they are asking for the same one.
//
// It keys on ImageSlug rather than the image tag. The slug carries the image digest and is
// what the SBOM is stored under, so it is the identity of the object being created. The tag
// is not: a mutable tag can point at two different digests at the same time, during a
// rollout or after a repush, and those are different images that must not share a result.
// rateLimitCacheKey leaves the digest out on purpose, because a registry rate limits by
// repository rather than by digest, which makes it the wrong identity here.
func sbomSingleflightKey(workload domain.ScanCommand, opts domain.RegistryOptions) string {
	return fmt.Sprintf("%s|%s|%s|http:%t|skiptls:%t", workload.ImageSlug, credentialsFingerprint(workload),
		opts.Platform, opts.InsecureUseHTTP, opts.InsecureSkipTLSVerify)
}

// checkCreateSBOM records a rate-limit (429) backoff entry in the tooManyRequests cache if the error indicates a rate-limited registry pull.
func (s *ScanService) checkCreateSBOM(err error, key string) {
	if isRegistryRateLimitedErr(err) {
		s.tooManyRequests.Set(key, true, ttl)
	}
}

// isRegistryRateLimitedErr reports whether err indicates the image pull was rate limited.
// It recognizes three shapes:
//   - domain.ErrTooManyRequests: the sentinel SidecarSBOMAdapter.CreateSBOM wraps its
//     returned error with once the sidecar scanner reports a 429 (see adapters/v1/sidecar.go).
//   - *transport.Error with StatusCode 429: what the in-process syft adapter would return
//     if the error reached here unwrapped.
//   - the rendered error text: stereoscope's registry provider formats the
//     go-containerregistry pull error with %+v, not %w, which severs the errors.As chain
//     for *transport.Error before it ever reaches here (mirrors
//     pkg/sbomscanner/v1.isRegistryRateLimited, which has the same problem on the sidecar
//     side of the same pull path).
func isRegistryRateLimitedErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, domain.ErrTooManyRequests) {
		return true
	}
	var transportError *transport.Error
	if errors.As(err, &transportError) && transportError.StatusCode == http.StatusTooManyRequests {
		return true
	}
	errStr := err.Error()
	return strings.Contains(errStr, "TOOMANYREQUESTS") ||
		strings.Contains(errStr, "429 Too Many Requests")
}

// GenerateSBOM implements the "Generate SBOM flow". It is live: cmd/http/main.go routes
// POST v1/generateSBOM here, through ValidateGenerateSBOM and the same rejection and scan
// metrics as the other flows.
func (s *ScanService) GenerateSBOM(ctx context.Context) error {
	ctx, span := otel.Tracer("").Start(ctx, "ScanService.GenerateSBOM")
	defer span.End()

	ctx = addTimestamp(ctx)

	// retrieve workload from context
	workload, ok := ctx.Value(domain.WorkloadKey{}).(domain.ScanCommand)
	if !ok {
		return domain.ErrCastingWorkload
	}

	sbom, storeErr, err := s.getOrCreateSBOM(ctx, workload)
	if err != nil {
		return err
	}

	// do not treat a timed out or too-large SBOM as a successful scan — mirrors the same
	// check in ScanCP/ScanCVE/ScanRegistry, which this flow had lost track of (see #540).
	// Ahead of storeErr so the size verdict stays the reported reason, as it did when the
	// store lived below this check.
	if sbom.Status == helpersv1.Incomplete || sbom.Status == helpersv1.TooLarge {
		reason := classifySBOMStatusWithAnnotation(sbom.Status, sbom.Annotations)
		_ = s.platform.ReportScanFailure(ctx, scanfailure.ScanFailureSBOMGeneration, reason, nil)
		return &domain.ScanError{Reason: reason, Err: domain.ErrIncompleteSBOM}
	}

	// getOrCreateSBOM already stored what it created, so there is nothing to write here.
	// Storing is the whole point of this endpoint though, so unlike the scan flows, which
	// carry on with an SBOM they could not persist, a failure there is reported as one.
	if storeErr != nil {
		_ = s.platform.ReportScanFailure(ctx, scanfailure.ScanFailureBackendPost,
			scanfailure.ReasonSBOMStorageFailed, storeErr)
		return &domain.ScanError{Reason: scanfailure.ReasonSBOMStorageFailed, Err: storeErr}
	}

	return nil
}

// Ready proxies the cveScanner's readiness
func (s *ScanService) Ready(ctx context.Context) bool {
	return s.cveScanner.Ready(ctx)
}

// ScanCP implements the "Scanning for CVEs" flow triggered by ContainerProfiles relevancy data.
func (s *ScanService) ScanCP(mainCtx context.Context) error {
	mainCtx, span := otel.Tracer("").Start(mainCtx, "ScanService.ScanCP")
	defer span.End()

	mainCtx = addTimestamp(mainCtx)

	// retrieve workload from context
	workload, ok := mainCtx.Value(domain.WorkloadKey{}).(domain.ScanCommand)
	if !ok {
		return domain.ErrCastingWorkload
	}
	name, _ := workload.Args[domain.ArgsName].(string)
	namespace, _ := workload.Args[domain.ArgsNamespace].(string)
	logger.L().Info("scan started",
		helpers.String("name", name),
		helpers.String("namespace", namespace),
		helpers.String("jobID", workload.JobID))

	scans, err := s.relevancyProvider.GetContainerRelevancyScans(mainCtx, namespace, name, s.partialRelevancy)
	if err != nil {
		return fmt.Errorf("getting container relevancy scans: %w", err)
	}

	for _, scan := range scans {
		imageTagNormalized := tools.NormalizeReference(scan.ImageTag)
		slug, err := names.ImageInfoToSlug(imageTagNormalized, scan.ImageID)
		if err != nil {
			logger.L().Ctx(mainCtx).Error("getting image slug, skipping scan", helpers.Error(err),
				helpers.String("imageTag", scan.ImageTag),
				helpers.String("imageID", scan.ImageID))
			continue // we need the slug
		}

		instanceIDSlug, _ := scan.InstanceID.GetSlug(false)

		// create a workload inside a new context
		subWorkload := domain.ScanCommand{
			CredentialsList:    workload.CredentialsList,
			ImageHash:          v1.NormalizeImageID(scan.ImageID, scan.ImageTag),
			Wlid:               scan.Wlid,
			ImageSlug:          slug,
			ImageTag:           scan.ImageTag,
			ImageTagNormalized: imageTagNormalized,
			JobID:              uuid.NewString(),
			ContainerName:      scan.ContainerName,
			InstanceID:         instanceIDSlug,
			ParentJobID:        workload.ParentJobID,
			Args:               workload.Args,
			Session:            workload.Session,
		}
		ctx := enrichContext(mainCtx, subWorkload, s.Version())

		// check if CVE manifest is already available
		cve := domain.CVEManifest{}
		if s.storage {
			cve, err = s.cveRepository.GetCVE(ctx, slug, s.sbomCreator.Version(), s.cveScanner.Version(), s.cveScanner.DBVersion(ctx))
			if err != nil {
				logger.L().Ctx(ctx).Warning("getting CVE", helpers.Error(err),
					helpers.String("imageSlug", slug))
				// no continue, we move on
			}
		}
		sbom := domain.SBOM{}

		// check if we need SBOM
		if cve.Content == nil || s.storage {
			var sbomErr error
			sbom, _, sbomErr = s.getOrCreateSBOM(ctx, subWorkload)
			if sbomErr != nil {
				logger.L().Ctx(ctx).Error("creating SBOM, skipping scan", helpers.Error(sbomErr),
					helpers.String("imageSlug", slug))
				continue // we need the SBOM
			}
			if !s.sbomGeneration && sbom.Content == nil {
				logger.L().Ctx(ctx).Error("missing SBOM, skipping scan",
					helpers.String("imageSlug", slug))
				continue // we need the SBOM
			}

			// check SBOM status
			if sbom.Status == helpersv1.Incomplete || sbom.Status == helpersv1.TooLarge {
				logger.L().Ctx(ctx).Warning("incomplete or too large SBOM, skipping scan",
					helpers.String("imageSlug", slug))
				_ = s.platform.ReportScanFailure(ctx, scanfailure.ScanFailureSBOMGeneration,
					classifySBOMStatusWithAnnotation(sbom.Status, sbom.Annotations), nil)
				continue // do not process this SBOM
			}
		}

		filteredCve := domain.CVEManifest{}
		var cveExceptionsComplete bool
		// if CVE manifest is not available, create it
		if cve.Content == nil {
			// scan for CVE
			cve, err = s.cveScanner.ScanSBOM(ctx, sbom)
			if err != nil {
				logger.L().Ctx(ctx).Error("scanning SBOM, skipping scan", helpers.Error(err),
					helpers.String("imageSlug", slug))
				_ = s.platform.ReportScanFailure(ctx, scanfailure.ScanFailureCVE,
					scanfailure.ReasonCVEMatchingFailed, err)
				continue // we need the CVE
			}

			// apply security exceptions for storage (copy — original stays intact for SubmitCVE)
			filteredCve, cveExceptionsComplete = s.applyExceptionsToManifest(ctx, cve)

			// store filtered CVE
			if s.storage {
				err = s.cveRepository.StoreCVE(ctx, filteredCve, false)
				if err != nil {
					logger.L().Ctx(ctx).Warning("storing CVE", helpers.Error(err),
						helpers.String("imageSlug", slug))
					// no continue, storing the CVE is not critical
				}
				err = s.cveRepository.StoreCVESummary(ctx, filteredCve, domain.CVEManifest{}, false)
				if err != nil {
					logger.L().Ctx(ctx).Warning("storing CVE summary", helpers.Error(err),
						helpers.String("imageSlug", slug))
					// no continue, storing the CVE summary is not critical
				}
			}
		} else {
			// A cached manifest was filtered against the exception set at store time.
			// Reconstruct the unfiltered manifest so the CURRENT exception set is
			// re-evaluated (deleted exceptions and ExpiredOnFix transitions
			// un-suppress findings) and SubmitCVE/StoreVEX receive the same
			// unfiltered data a cache miss would produce.
			prevIgnored := v1.IgnoredMatchKeys(cve.Content)
			cve.Content = v1.RestoreSuppressedMatches(cve.Content)
			filteredCve, cveExceptionsComplete = s.applyExceptionsToManifest(ctx, cve)

			if s.storage {
				curIgnored := v1.IgnoredMatchKeys(filteredCve.Content)
				if !maps.Equal(prevIgnored, curIgnored) {
					// Persist additions freely, but never persist removals when the
					// exception set is incomplete: a transient SecurityException CRD
					// list failure must not look like a deletion and wipe suppression
					// from the stored manifest.
					hasRemovals := false
					for k := range prevIgnored {
						if _, ok := curIgnored[k]; !ok {
							hasRemovals = true
							break
						}
					}
					if cveExceptionsComplete || !hasRemovals {
						err = s.cveRepository.StoreCVE(ctx, filteredCve, false)
						if err != nil {
							logger.L().Ctx(ctx).Warning("storing CVE with exceptions", helpers.Error(err),
								helpers.String("imageSlug", slug))
						}
						err = s.cveRepository.StoreCVESummary(ctx, filteredCve, domain.CVEManifest{}, false)
						if err != nil {
							logger.L().Ctx(ctx).Warning("storing CVE summary with exceptions", helpers.Error(err),
								helpers.String("imageSlug", slug))
						}
					}
				}
			}
		}

		// generate SBOM' from SBOM and relevant files
		sbomp := domain.SBOM{}
		if s.storage {
			sbomp, err = filterSBOM(sbom, scan.InstanceID, scan.Wlid, scan.RelevantFiles, scan.Labels, scan.Completion)
			if err != nil {
				logger.L().Ctx(ctx).Error("filtering SBOM, skipping scan", helpers.Error(err),
					helpers.String("instanceID", scan.InstanceID.GetStringFormatted()))
				continue // we need the SBOM'
			}
			if s.storeFilteredSbom {
				err = s.sbomRepository.StoreSBOM(ctx, sbomp, true)
				if err != nil {
					logger.L().Ctx(ctx).Warning("storing filtered SBOM", helpers.Error(err),
						helpers.String("instanceID", scan.InstanceID.GetStringFormatted()))
					// no continue, storing the SBOM' is not critical
				}
			}
		}

		// with SBOM' we can scan for CVE'
		cvep := domain.CVEManifest{}
		if sbomp.Content != nil {
			// scan for CVE'
			cvep, err = s.cveScanner.ScanSBOM(ctx, sbomp)
			if err != nil {
				logger.L().Ctx(ctx).Error("scanning filtered SBOM, skipping scan", helpers.Error(err),
					helpers.String("instanceID", scan.InstanceID.GetStringFormatted()))
				continue // we need the CVE'
			}

			// apply security exceptions for storage (copy — original stays intact for SubmitCVE)
			filteredCvep, cvepExceptionsComplete := s.applyExceptionsToManifest(ctx, cvep)

			// store filtered CVE'
			if s.storage {
				filteredCvep.Wlid = scan.Wlid
				err = s.cveRepository.StoreCVE(ctx, filteredCvep, true)
				if err != nil {
					logger.L().Ctx(ctx).Warning("storing CVEp", helpers.Error(err),
						helpers.String("instanceID", scan.InstanceID.GetStringFormatted()))
					// no continue, storing the CVE' is not critical
				}
				// Summary uses original cve (all matches for total counts) and
				// filteredCvep (exceptions applied to relevant matches only).
				err = s.cveRepository.StoreCVESummary(ctx, cve, filteredCvep, true)
				if err != nil {
					logger.L().Ctx(ctx).Warning("storing CVE summary", helpers.Error(err),
						helpers.String("imageSlug", slug))
					// no continue, storing the CVE summary is not critical
				}
				if cveExceptionsComplete && cvepExceptionsComplete {
					s.storeVEX(ctx, filteredCve, filteredCvep, true, slug)
				}
			}
		}
		// submit CVE manifest to platform
		err = s.platform.SubmitCVE(ctx, cve, cvep)
		if err != nil {
			logger.L().Ctx(ctx).Warning("submitting CVEs", helpers.Error(err),
				helpers.String("instanceID", scan.InstanceID.GetStringFormatted()))
			_ = s.platform.ReportScanFailure(ctx, scanfailure.ScanFailureBackendPost,
				scanfailure.ReasonResultUploadFailed, err)
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
		cve, err = s.cveRepository.GetCVE(ctx, workload.ImageSlug, s.sbomCreator.Version(), s.cveScanner.Version(), s.cveScanner.DBVersion(ctx))
		if err != nil {
			logger.L().Ctx(ctx).Warning("getting CVE", helpers.Error(err),
				helpers.String("imageSlug", workload.ImageSlug))
		}
	}

	sbom := domain.SBOM{}
	// check if we need SBOM
	if cve.Content == nil {
		var sbomErr error
		sbom, _, sbomErr = s.getOrCreateSBOM(ctx, workload)
		if sbomErr != nil {
			var scanErr *domain.ScanError
			if errors.As(sbomErr, &scanErr) {
				return &domain.ScanError{Reason: scanErr.Reason, Err: fmt.Errorf("creating SBOM: %w", scanErr.Err)}
			}
			reason := classifySBOMError(sbomErr)
			return &domain.ScanError{Reason: reason, Err: fmt.Errorf("creating SBOM: %w", sbomErr)}
		}
		if !s.sbomGeneration && sbom.Content == nil {
			logger.L().Ctx(ctx).Warning("missing SBOM",
				helpers.String("imageSlug", workload.ImageSlug))
			return domain.ErrMissingSBOM
		}

		// do not process timed out SBOM
		if sbom.Status == helpersv1.Incomplete || sbom.Status == helpersv1.TooLarge {
			reason := classifySBOMStatusWithAnnotation(sbom.Status, sbom.Annotations)
			_ = s.platform.ReportScanFailure(ctx, scanfailure.ScanFailureSBOMGeneration, reason, nil)
			return &domain.ScanError{Reason: reason, Err: domain.ErrIncompleteSBOM}
		}
	}

	// if CVE manifest is not available, create it
	if cve.Content == nil {
		// scan for CVE
		cve, err = s.cveScanner.ScanSBOM(ctx, sbom)
		if err != nil {
			_ = s.platform.ReportScanFailure(ctx, scanfailure.ScanFailureCVE,
				scanfailure.ReasonCVEMatchingFailed, err)
			return &domain.ScanError{Reason: scanfailure.ReasonCVEMatchingFailed, Err: fmt.Errorf("scanning SBOM: %w", err)}
		}

		// apply security exceptions for storage (copy — original stays intact for SubmitCVE)
		filteredCve, exceptionsComplete := s.applyExceptionsToManifest(ctx, cve)

		// store filtered CVE
		if s.storage {
			err = s.cveRepository.StoreCVE(ctx, filteredCve, false)
			if err != nil {
				logger.L().Ctx(ctx).Warning("storing CVE", helpers.Error(err),
					helpers.String("imageSlug", workload.ImageSlug))
			}
			err = s.cveRepository.StoreCVESummary(ctx, filteredCve, domain.CVEManifest{}, false)
			if err != nil {
				logger.L().Ctx(ctx).Warning("storing CVE summary", helpers.Error(err),
					helpers.String("imageSlug", workload.ImageSlug))
			}
			// Only publish VEX built from a known-complete exception set, matching how
			// ScanCP gates its own call: a degraded fetch would otherwise emit a document
			// asserting fewer suppressions than the user actually configured.
			if exceptionsComplete {
				s.storeVEX(ctx, filteredCve, filteredCve, false, workload.ImageSlug)
			}
		}
	} else {
		// A cached manifest was filtered against the exception set at store time.
		// Reconstruct the unfiltered manifest so the CURRENT exception set is
		// re-evaluated (deleted exceptions and ExpiredOnFix transitions
		// un-suppress findings) and SubmitCVE/StoreVEX receive the same unfiltered
		// data a cache miss would produce.
		prevIgnored := v1.IgnoredMatchKeys(cve.Content)
		cve.Content = v1.RestoreSuppressedMatches(cve.Content)
		filteredCve, exceptionsComplete := s.applyExceptionsToManifest(ctx, cve)

		if s.storage {
			curIgnored := v1.IgnoredMatchKeys(filteredCve.Content)
			if !maps.Equal(prevIgnored, curIgnored) {
				// Persist additions freely, but never persist removals when the
				// exception set is incomplete: a transient SecurityException CRD
				// list failure must not look like a deletion and wipe suppression
				// from the stored manifest.
				hasRemovals := false
				for k := range prevIgnored {
					if _, ok := curIgnored[k]; !ok {
						hasRemovals = true
						break
					}
				}
				if exceptionsComplete || !hasRemovals {
					err = s.cveRepository.StoreCVE(ctx, filteredCve, false)
					if err != nil {
						logger.L().Ctx(ctx).Warning("storing CVE with exceptions", helpers.Error(err),
							helpers.String("imageSlug", workload.ImageSlug))
					}
					err = s.cveRepository.StoreCVESummary(ctx, filteredCve, domain.CVEManifest{}, false)
					if err != nil {
						logger.L().Ctx(ctx).Warning("storing CVE summary with exceptions", helpers.Error(err),
							helpers.String("imageSlug", workload.ImageSlug))
					}
					// The stored manifest just changed, so the VEX document describing it is
					// now stale. Republish it, but only from a known-complete exception set,
					// the same rule the cache-miss path follows.
					//
					// The manifest is persisted on the looser `exceptionsComplete ||
					// !hasRemovals` condition because a partial set can only under-suppress,
					// never wrongly un-suppress, so additions are safe to keep. A VEX document
					// is a published assertion about which CVEs are suppressed, and one built
					// from a partial set understates that. Leaving the previous document in
					// place, written when the set was complete, beats replacing it with a
					// weaker claim, so the two can briefly disagree until a complete scan.
					if exceptionsComplete {
						s.storeVEX(ctx, filteredCve, filteredCve, false, workload.ImageSlug)
					}
				}
			}
		}
	}

	// submit CVE manifest to platform, only if we have a wlid
	if workload.Wlid != "" {
		err = s.platform.SubmitCVE(ctx, cve, domain.CVEManifest{})
		if err != nil {
			_ = s.platform.ReportScanFailure(ctx, scanfailure.ScanFailureBackendPost,
				scanfailure.ReasonResultUploadFailed, err)
			return &domain.ScanError{Reason: scanfailure.ReasonResultUploadFailed, Err: fmt.Errorf("submitting CVEs: %w", err)}
		}
	}

	logger.L().Info("scan complete",
		helpers.String("imageSlug", workload.ImageSlug),
		helpers.String("instanceID", workload.InstanceID),
		helpers.String("jobID", workload.JobID))
	return nil
}

// ScanRegistry implements the "Scanning for CVEs" flow triggered by a manual/registry scan request.
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

	// check if CVE manifest is already available
	cve := domain.CVEManifest{}
	if s.storage {
		cve, err = s.cveRepository.GetCVE(ctx, workload.ImageSlug, s.sbomCreator.Version(), s.cveScanner.Version(), s.cveScanner.DBVersion(ctx))
		if err != nil {
			logger.L().Ctx(ctx).Warning("getting CVE", helpers.Error(err),
				helpers.String("imageSlug", workload.ImageSlug))
		}
	}

	sbom := domain.SBOM{}
	if cve.Content == nil {
		var sbomErr error
		sbom, _, sbomErr = s.getOrCreateSBOM(ctx, workload)
		if sbomErr != nil {
			repErr := s.platform.ReportError(ctx, sbomErr)
			if repErr != nil {
				logger.L().Ctx(ctx).Warning("telemetry error", helpers.Error(repErr),
					helpers.String("imageSlug", workload.ImageSlug))
			}
			var scanErr *domain.ScanError
			if errors.As(sbomErr, &scanErr) {
				return scanErr
			}
			reason := classifySBOMError(sbomErr)
			return &domain.ScanError{Reason: reason, Err: sbomErr}
		}

		// do not process timed out SBOM
		if sbom.Status == helpersv1.Incomplete || sbom.Status == helpersv1.TooLarge {
			reason := classifySBOMStatusWithAnnotation(sbom.Status, sbom.Annotations)
			_ = s.platform.ReportScanFailure(ctx, scanfailure.ScanFailureSBOMGeneration, reason, nil)
			return &domain.ScanError{Reason: reason, Err: domain.ErrIncompleteSBOM}
		}

		// scan for CVE
		cve, err = s.cveScanner.ScanSBOM(ctx, sbom)
		if err != nil {
			repErr := s.platform.ReportError(ctx, err)
			if repErr != nil {
				logger.L().Ctx(ctx).Warning("telemetry error", helpers.Error(repErr),
					helpers.String("imageSlug", workload.ImageSlug))
			}
			_ = s.platform.ReportScanFailure(ctx, scanfailure.ScanFailureCVE,
				scanfailure.ReasonCVEMatchingFailed, err)
			return &domain.ScanError{Reason: scanfailure.ReasonCVEMatchingFailed, Err: err}
		}

		// apply security exceptions for storage (copy — original stays intact for SubmitCVE)
		filteredCve, exceptionsComplete := s.applyExceptionsToManifest(ctx, cve)

		// store filtered CVE
		if s.storage {
			err = s.cveRepository.StoreCVE(ctx, filteredCve, false)
			if err != nil {
				logger.L().Ctx(ctx).Warning("storing CVE", helpers.Error(err),
					helpers.String("imageSlug", workload.ImageSlug))
			}
			err = s.cveRepository.StoreCVESummary(ctx, filteredCve, domain.CVEManifest{}, false)
			if err != nil {
				logger.L().Ctx(ctx).Warning("storing CVE summary", helpers.Error(err),
					helpers.String("imageSlug", workload.ImageSlug))
			}
			// Only publish VEX built from a known-complete exception set, matching how
			// ScanCVE and ScanCP gate their own calls: a degraded fetch would otherwise
			// emit a document asserting fewer suppressions than the user configured.
			if exceptionsComplete {
				s.storeVEX(ctx, filteredCve, filteredCve, false, workload.ImageSlug)
			}
		}
	} else {
		// A cached manifest was filtered against the exception set at store time.
		// Reconstruct the unfiltered manifest so the CURRENT exception set is
		// re-evaluated (deleted exceptions and ExpiredOnFix transitions
		// un-suppress findings) and SubmitCVE/StoreVEX receive the same
		// unfiltered data a cache miss would produce.
		prevIgnored := v1.IgnoredMatchKeys(cve.Content)
		cve.Content = v1.RestoreSuppressedMatches(cve.Content)
		filteredCve, exceptionsComplete := s.applyExceptionsToManifest(ctx, cve)

		if s.storage {
			curIgnored := v1.IgnoredMatchKeys(filteredCve.Content)
			if !maps.Equal(prevIgnored, curIgnored) {
				// Persist additions freely, but never persist removals when the
				// exception set is incomplete: a transient SecurityException CRD
				// list failure must not look like a deletion and wipe suppression
				// from the stored manifest.
				hasRemovals := false
				for k := range prevIgnored {
					if _, ok := curIgnored[k]; !ok {
						hasRemovals = true
						break
					}
				}
				if exceptionsComplete || !hasRemovals {
					err = s.cveRepository.StoreCVE(ctx, filteredCve, false)
					if err != nil {
						logger.L().Ctx(ctx).Warning("storing CVE with exceptions", helpers.Error(err),
							helpers.String("imageSlug", workload.ImageSlug))
					}
					err = s.cveRepository.StoreCVESummary(ctx, filteredCve, domain.CVEManifest{}, false)
					if err != nil {
						logger.L().Ctx(ctx).Warning("storing CVE summary with exceptions", helpers.Error(err),
							helpers.String("imageSlug", workload.ImageSlug))
					}
					// The stored manifest just changed, so the VEX document describing it is
					// now stale. Republish it, but only from a known-complete exception set,
					// the same rule the cache-miss path follows.
					//
					// The manifest is persisted on the looser `exceptionsComplete ||
					// !hasRemovals` condition because a partial set can only under-suppress,
					// never wrongly un-suppress, so additions are safe to keep. A VEX document
					// is a published assertion about which CVEs are suppressed, and one built
					// from a partial set understates that. Leaving the previous document in
					// place, written when the set was complete, beats replacing it with a
					// weaker claim, so the two can briefly disagree until a complete scan.
					if exceptionsComplete {
						s.storeVEX(ctx, filteredCve, filteredCve, false, workload.ImageSlug)
					}
				}
			}
		}
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
		_ = s.platform.ReportScanFailure(ctx, scanfailure.ScanFailureBackendPost,
			scanfailure.ReasonResultUploadFailed, err)
		return &domain.ScanError{Reason: scanfailure.ReasonResultUploadFailed, Err: err}
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

// storeVEX writes the VEX document for a scanned image when VEX generation is enabled,
// and is a no-op otherwise. Every CVE-scan flow stores VEX the same way, so they share
// this rather than each carrying its own copy: the reason ScanCVE ended up with none at
// all was that the call had to be ported to each flow by hand.
//
// A failure is logged rather than returned. The CVE manifest is already stored at every
// call site, so the scan result stands without the VEX document.
func (s *ScanService) storeVEX(ctx context.Context, cve, cvep domain.CVEManifest, withRelevancy bool, imageSlug string) {
	if !s.vexGeneration {
		return
	}
	if err := s.cveRepository.StoreVEX(ctx, cve, cvep, withRelevancy); err != nil {
		logger.L().Ctx(ctx).Warning("storing VEX", helpers.Error(err),
			helpers.String("imageSlug", imageSlug))
	}
}

// applyExceptionsToManifest returns a filtered copy of the CVE manifest with
// SecurityException policies applied. The original manifest is not mutated,
// so callers can still use it for SubmitCVE (cloud reporting). The returned
// bool reports whether the current exception set is known complete. A hard
// fetch failure returns the manifest unfiltered with complete=false; a degraded
// fetch (ErrExceptionsDegraded) still applies the partial set but reports
// complete=false, so callers never persist "removals" computed from an
// incomplete set.
func (s *ScanService) applyExceptionsToManifest(ctx context.Context, cve domain.CVEManifest) (domain.CVEManifest, bool) {
	if cve.Content == nil {
		return cve, false
	}
	exceptions, stats, err := s.platform.GetCVEExceptions(ctx)
	degraded := errors.Is(err, domain.ErrExceptionsDegraded)
	if degraded && s.metrics != nil {
		s.metrics.ExceptionsDegradedCounter.Add(ctx, 1)
	}
	s.recordExceptionsExpired(ctx, stats)
	if err != nil && !degraded {
		logger.L().Ctx(ctx).Warning("failed to get CVE exceptions for filtering", helpers.Error(err))
		return cve, false
	}
	if s.metrics != nil {
		s.metrics.ExceptionsActiveGauge.Record(ctx, int64(len(exceptions)))
	}
	if len(exceptions) == 0 {
		return cve, !degraded
	}
	filtered := cve
	if cve.Labels != nil {
		filtered.Labels = maps.Clone(cve.Labels)
	}
	if cve.Annotations != nil {
		filtered.Annotations = maps.Clone(cve.Annotations)
	}
	docCopy := cve.Content.DeepCopy()
	matchedBySource := v1.ApplySecurityExceptions(docCopy, exceptions, s.eventRecorder)
	s.recordExceptionsMatched(ctx, matchedBySource)
	filtered.Content = docCopy
	return filtered, !degraded
}

// recordExceptionsExpired reports, per SecurityException/ClusterSecurityException sourceKind,
// how many exceptions applyExceptionsToManifest's GetCVEExceptions call skipped this scan
// because their expiresAt had passed (see domain.ExceptionStats). No-op when metrics aren't
// configured or nothing expired this call.
func (s *ScanService) recordExceptionsExpired(ctx context.Context, stats domain.ExceptionStats) {
	if s.metrics == nil {
		return
	}
	for source, count := range stats.ExpiredBySource {
		if count == 0 {
			continue
		}
		s.metrics.ExceptionsExpiredCounter.Add(ctx, int64(count),
			metric.WithAttributes(attribute.String("sourceKind", source)))
	}
}

// recordExceptionsMatched reports, per SecurityException/ClusterSecurityException sourceKind,
// how many CVE matches ApplySecurityExceptions suppressed this scan. No-op when metrics
// aren't configured or nothing was suppressed this call.
func (s *ScanService) recordExceptionsMatched(ctx context.Context, matchedBySource map[string]int) {
	if s.metrics == nil {
		return
	}
	for source, count := range matchedBySource {
		if count == 0 {
			continue
		}
		s.metrics.ExceptionsMatchedCounter.Add(ctx, int64(count),
			metric.WithAttributes(attribute.String("sourceKind", source)))
	}
}

// addTimestamp attaches the current timestamp to the context.
func addTimestamp(ctx context.Context) context.Context {
	return context.WithValue(ctx, domain.TimestampKey{}, time.Now().Unix())
}

// enrichContext populates the context with scan command metadata and tracing attributes.
func enrichContext(ctx context.Context, workload domain.ScanCommand, scannerVersion string) context.Context {
	// generate unique scanID and add to context

	scanID := generateScanID(workload, scannerVersion)
	ctx = context.WithValue(ctx, domain.ScanIDKey{}, scanID)
	// add workload to context
	ctx = context.WithValue(ctx, domain.WorkloadKey{}, workload)
	return ctx
}

// generateScanID computes a unique hash ID for a scan execution.
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

// optionsFromWorkload converts scan command credentials into domain.RegistryOptions.
func optionsFromWorkload(ctx context.Context, workload domain.ScanCommand) domain.RegistryOptions {
	options := domain.RegistryOptions{}
	options.Credentials = registryCredentialsFromCredentialsList(workload.CredentialsList)

	if useHTTP, ok := workload.Args[domain.AttributeUseHTTP]; ok {
		if b, isBool := useHTTP.(bool); isBool {
			options.InsecureUseHTTP = b
		} else {
			logger.L().Ctx(ctx).Warning("ignoring non-boolean value for registry option",
				helpers.String("key", domain.AttributeUseHTTP),
				helpers.String("type", fmt.Sprintf("%T", useHTTP)),
				helpers.String("imageSlug", workload.ImageSlug))
		}
	}
	if skipTLSVerify, ok := workload.Args[domain.AttributeSkipTLSVerify]; ok {
		if b, isBool := skipTLSVerify.(bool); isBool {
			options.InsecureSkipTLSVerify = b
		} else {
			logger.L().Ctx(ctx).Warning("ignoring non-boolean value for registry option",
				helpers.String("key", domain.AttributeSkipTLSVerify),
				helpers.String("type", fmt.Sprintf("%T", skipTLSVerify)),
				helpers.String("imageSlug", workload.ImageSlug))
		}
	}
	if platform, ok := workload.Args[domain.ArgsPlatform]; ok {
		if p, isString := platform.(string); isString {
			options.Platform = p
		} else {
			logger.L().Ctx(ctx).Warning("ignoring non-string value for registry option",
				helpers.String("key", domain.ArgsPlatform),
				helpers.String("type", fmt.Sprintf("%T", platform)),
				helpers.String("imageSlug", workload.ImageSlug))
		}
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

// registryCredentialsFromCredentialsList converts auth configurations into domain registry credentials.
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
		username, password := cred.Username, cred.Password
		if username == "" && password == "" && cred.Auth != "" {
			username, password = credentialsFromAuth(cred.Auth)
		}
		if username != "" && password != "" {
			rc.Username = username
			rc.Password = password
		}

		registryCredentials[i] = rc
	}
	return registryCredentials
}

// credentialsFromAuth decodes the standard Docker "auth" field: base64 of "username:password".
// It's the canonical field in a .dockerconfigjson pull secret; username/password are only
// supplementary and are often absent. Kubernetes' documented way to reuse an existing docker
// login (kubectl create secret generic --from-file=.dockerconfigjson=~/.docker/config.json)
// produces entries where only auth is set, so falling back to it here is required for those
// credentials to reach the registry pull at all, rather than being silently dropped.
func credentialsFromAuth(auth string) (username, password string) {
	decoded, err := base64.StdEncoding.DecodeString(auth)
	if err != nil {
		return "", ""
	}
	username, password, found := strings.Cut(string(decoded), ":")
	if !found {
		return "", ""
	}
	return username, password
}

// parseAuthorityFromServerAddress extracts the authority host:port from a server address.
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

// filterSBOM filters the SBOM package tree based on container profile relevancy information.
func filterSBOM(sbom domain.SBOM, instanceID instanceidhandler.IInstanceID, wlid string, relevantFiles mapset.Set[string], labels map[string]string, completion string) (domain.SBOM, error) {
	name, err := instanceID.GetSlug(false)
	if err != nil {
		return domain.SBOM{}, fmt.Errorf("getting slug from instance id: %w", err)
	}
	filteredSBOM := domain.SBOM{
		Name: name,
		Annotations: map[string]string{
			helpersv1.CompletionMetadataKey:    completion,
			helpersv1.ContainerNameMetadataKey: labels[helpersv1.ContainerNameMetadataKey],
			helpersv1.ImageIDMetadataKey:       sbom.Annotations[helpersv1.ImageIDMetadataKey],
			helpersv1.ImageTagMetadataKey:      sbom.Annotations[helpersv1.ImageTagMetadataKey],
			helpersv1.InstanceIDMetadataKey:    instanceID.GetStringFormatted(),
			helpersv1.StatusMetadataKey:        sbom.Annotations[helpersv1.StatusMetadataKey],
			helpersv1.WlidMetadataKey:          wlid,
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
	filteredSBOM.Labels[helpersv1.ArtifactTypeMetadataKey] = helpersv1.ContainerArtifactType
	addedArtifactIDs := mapset.NewSet[string]()
	addedFileIDs := mapset.NewSet[string]()
	addedRelationshipIDs := mapset.NewSet[string]()

	// Split the relevant files that carry a placeholder, because the two kinds behave
	// differently. DynamicIdentifier ("⋯") stands for exactly one segment, so such a path
	// can only ever match one with the same number of segments and is indexed by that count
	// (see #448). WildcardIdentifier ("*") stands for zero or more segments: the detector
	// produces it by collapsing runs of "⋯" (so "/a/⋯/⋯/b" is stored as "/a/*/b"),
	// and it can match a path with any number of segments, so no bucket holds it and it has
	// to be compared against every file.
	dynamicPathsBySegmentCount := make(map[int][]string)
	var wildcardPaths []string
	relevantFiles.Each(func(file string) bool {
		switch {
		case strings.Contains(file, dynamicpathdetector.WildcardIdentifier):
			wildcardPaths = append(wildcardPaths, file)
		case strings.Contains(file, dynamicpathdetector.DynamicIdentifier):
			segmentCount := strings.Count(file, "/")
			dynamicPathsBySegmentCount[segmentCount] = append(dynamicPathsBySegmentCount[segmentCount], file)
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
			// then try dynamic match (expensive lookup): the one bucket a fixed-width
			// placeholder path could be in, plus the wildcard paths, which fit no bucket
			realPath := f.Location.RealPath
			if matchesAnyDynamicPath(realPath, dynamicPathsBySegmentCount[strings.Count(realPath, "/")]) ||
				matchesAnyDynamicPath(realPath, wildcardPaths) {
				addedFileIDs.Add(f.ID)
				filteredSBOM.Content.Files = append(filteredSBOM.Content.Files, f)
			}
		}
	}

	// filter relevant relationships and their transitively-relevant ancestor artifacts. A
	// relationship is relevant if its child is a relevant file, or transitively, if its child
	// is an artifact already known to be relevant (e.g. a package nested inside another
	// package's archive). This walks the relationship graph to a fixed point instead of a
	// fixed number of passes: Syft does not document or guarantee any particular relationship
	// ordering, and a fixed number of passes can silently drop artifacts nested more than one
	// level below the direct file owner depending on that order (see #514).
	childToRelationships := make(map[string][]v1beta1.SyftRelationship, len(sbom.Content.ArtifactRelationships))
	for _, relationship := range sbom.Content.ArtifactRelationships {
		childToRelationships[relationship.Child] = append(childToRelationships[relationship.Child], relationship)
	}

	// Compute the closure first (which relationships/artifacts are relevant) without emitting
	// anything: addedFileIDs.ToSlice() has no stable order, so a traversal that appends
	// relationships as it discovers them would make the output order vary between calls on
	// the same input whenever there's more than one relevant file. Emitting afterward, in a
	// single pass over sbom.Content.ArtifactRelationships, keeps the output in the same
	// deterministic source order the pre-fix code always had.
	relationshipsArtifacts := mapset.NewSet[string]()
	frontier := addedFileIDs.ToSlice()
	for len(frontier) > 0 {
		var next []string
		for _, childID := range frontier {
			for _, relationship := range childToRelationships[childID] {
				relationshipID := getRelationshipID(relationship)
				if addedRelationshipIDs.Contains(relationshipID) {
					continue
				}
				addedRelationshipIDs.Add(relationshipID)
				if relationshipsArtifacts.Add(relationship.Parent) {
					next = append(next, relationship.Parent)
				}
			}
		}
		frontier = next
	}

	for _, relationship := range sbom.Content.ArtifactRelationships {
		if addedRelationshipIDs.Contains(getRelationshipID(relationship)) {
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

// matchesAnyDynamicPath reports whether path is matched by any of the placeholder-carrying
// relevant-file paths in candidates.
func matchesAnyDynamicPath(path string, candidates []string) bool {
	for _, candidate := range candidates {
		if dynamicpathdetector.CompareDynamic(candidate, path) {
			return true
		}
	}
	return false
}

// getRelationshipID returns a unique string identifier for a Syft relationship.
func getRelationshipID(relationship v1beta1.SyftRelationship) string {
	return fmt.Sprintf("%s/%s/%s", relationship.Parent, relationship.Child, relationship.Type)
}

// ValidateGenerateSBOM validates the workload for the GenerateSBOM flow and enriches the context.
func (s *ScanService) ValidateGenerateSBOM(ctx context.Context, workload domain.ScanCommand) (context.Context, error) {
	_, span := otel.Tracer("").Start(ctx, "ScanService.ValidateGenerateSBOM")
	defer span.End()

	ctx = enrichContext(ctx, workload, s.Version())
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
	if _, ok := s.tooManyRequests.Get(rateLimitCacheKey(workload)); ok {
		return ctx, domain.ErrTooManyRequests
	}
	return ctx, nil
}

// ValidateScanCP validates the workload for the ScanCP flow and enriches the context.
func (s *ScanService) ValidateScanCP(ctx context.Context, workload domain.ScanCommand) (context.Context, error) {
	_, span := otel.Tracer("").Start(ctx, "ScanService.ValidateScanCP")
	defer span.End()
	ctx = enrichContext(ctx, workload, s.Version())
	// validate inputs
	name, _ := workload.Args[domain.ArgsName].(string)
	namespace, _ := workload.Args[domain.ArgsNamespace].(string)
	if name == "" || namespace == "" {
		return ctx, domain.ErrMissingCpInfo
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

// ValidateScanCVE validates the workload for the ScanCVE flow and enriches the context.
func (s *ScanService) ValidateScanCVE(ctx context.Context, workload domain.ScanCommand) (context.Context, error) {
	_, span := otel.Tracer("").Start(ctx, "ScanService.ValidateScanCVE")
	defer span.End()

	ctx = enrichContext(ctx, workload, s.Version())
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
	if _, ok := s.tooManyRequests.Get(rateLimitCacheKey(workload)); ok {
		return ctx, domain.ErrTooManyRequests
	}
	return ctx, nil
}

// ValidateScanRegistry validates the workload for the ScanRegistry flow and enriches the context.
func (s *ScanService) ValidateScanRegistry(ctx context.Context, workload domain.ScanCommand) (context.Context, error) {
	_, span := otel.Tracer("").Start(ctx, "ScanService.ValidateScanRegistry")
	defer span.End()

	ctx = enrichContext(ctx, workload, s.Version())
	// validate inputs
	if workload.ImageTagNormalized == "" || workload.ImageSlug == "" {
		return ctx, domain.ErrMissingImageInfo
	}
	// add imageSlug to parent span
	if parentSpan := trace.SpanFromContext(ctx); parentSpan != nil {
		parentSpan.SetAttributes(attribute.String("imageSlug", workload.ImageSlug))
		parentSpan.SetAttributes(attribute.String("version", os.Getenv("RELEASE")))
		parentSpan.SetAttributes(attribute.String("wlid", workload.Wlid))
		ctx = trace.ContextWithSpan(ctx, parentSpan)
	}
	// check if previous image pull resulted in TOOMANYREQUESTS error
	if _, ok := s.tooManyRequests.Get(rateLimitCacheKey(workload)); ok {
		return ctx, domain.ErrTooManyRequests
	}
	return ctx, nil
}

// Version returns the combined SBOM creator and CVE scanner version string.
func (s *ScanService) Version() string {
	return s.sbomCreator.Version() + "-" + s.cveScanner.Version()
}

// getSBOM retrieves a stored SBOM, deleting and returning empty if it is outdated or stale due to changed size/memory limits.
func (s *ScanService) getSBOM(ctx context.Context, name string, creatorVersion string) (domain.SBOM, error) {
	sbom, err := s.sbomRepository.GetSBOM(ctx, name, creatorVersion)
	if err != nil {
		if errors.Is(err, domain.ErrOutdatedSBOM) {
			if sbom.Status == helpersv1.TooLarge {
				logger.L().Ctx(ctx).Info("SBOM is outdated and too large, deleting to trigger a fresh scan",
					helpers.String("name", name))
				// Delete both unfiltered and filtered SBOMs
				if delErr := s.sbomRepository.DeleteSBOM(ctx, name); delErr != nil {
					logger.L().Ctx(ctx).Warning("failed to delete outdated SBOM", helpers.Error(delErr), helpers.String("name", name))
					return domain.SBOM{}, nil
				}
			}
			return domain.SBOM{}, nil
		}
		return sbom, err
	}
	if sbom.Content == nil {
		return sbom, nil
	}

	if sbom.Status == helpersv1.TooLarge {
		reason := sbom.Annotations[domain.StatusReasonAnnotationKey]
		stale := false

		switch reason {
		case domain.ReasonImageTooLarge:
			limitStr, ok := sbom.Annotations[domain.MaxImageSizeAnnotationKey]
			if !ok {
				stale = true
			} else {
				currentLimit := s.sbomCreator.GetMaxImageSize()
				if limitStr != fmt.Sprintf("%d", currentLimit) {
					stale = true
				}
			}
		case domain.ReasonSBOMTooLarge:
			limitStr, ok := sbom.Annotations[domain.MaxSBOMSizeAnnotationKey]
			if !ok {
				stale = true
			} else {
				currentLimit := s.sbomCreator.GetMaxSBOMSize()
				if limitStr != fmt.Sprintf("%d", currentLimit) {
					stale = true
				}
			}
		case domain.ReasonScannerOOM:
			limitStr, ok := sbom.Annotations[domain.ScannerMemoryLimitAnnotationKey]
			if !ok {
				stale = true
			} else {
				currentLimit := s.sbomCreator.GetMemoryLimit()
				if limitStr != currentLimit {
					stale = true
				}
			}
		default:
			// No status reason annotation or unrecognized reason.
			// Treat as stale to ensure retroactive cleanup.
			stale = true
		}

		if stale {
			logger.L().Ctx(ctx).Info("SBOM is stale/frozen due to changed limits, deleting to trigger a fresh scan",
				helpers.String("name", name),
				helpers.String("reason", reason))
			// Delete both unfiltered and filtered SBOMs
			if delErr := s.sbomRepository.DeleteSBOM(ctx, name); delErr != nil {
				logger.L().Ctx(ctx).Warning("failed to delete stale SBOM", helpers.Error(delErr), helpers.String("name", name))
				return sbom, nil
			}
			// Return empty domain.SBOM to trigger a fresh scan
			return domain.SBOM{}, nil
		}
	}

	return sbom, nil
}

// getOrCreateSBOM retrieves an existing SBOM from storage, or creates and stores one via singleflight
// deduplication if multiple goroutines race to build an SBOM for the same image.
// sbomCreation is what the singleflight worker hands back: the SBOM, plus whether storing
// it failed. Every caller racing a key gets the same one, so a waiter learns the outcome of
// the shared store rather than repeating it.
type sbomCreation struct {
	sbom     domain.SBOM
	storeErr error
}

// getOrCreateSBOM returns the SBOM for workload and the error from storing it, if it was
// created and stored here. A non-nil store error is not fatal on its own: the SBOM is still
// usable, and only GenerateSBOM, which exists to store it, treats it as a failure.
func (s *ScanService) getOrCreateSBOM(ctx context.Context, workload domain.ScanCommand) (domain.SBOM, error, error) {
	if !s.sbomGeneration {
		return domain.SBOM{}, nil, nil
	}

	opts := optionsFromWorkload(ctx, workload)
	key := sbomSingleflightKey(workload, opts)

	// Detach workerCtx from caller cancellation so the singleflight worker job completes for all waiters even if the leader cancels early
	workerCtx := context.WithoutCancel(ctx)

	// ran reports whether this caller's own closure was the one singleflight executed.
	// singleflight's res.Shared cannot answer that: it means the result was handed to more
	// than one caller, so it is true for the leader too, and counting on it would report the
	// caller that did the work as one of the callers that were spared it. Only read in the
	// res branch below, where receiving happens-after the closure returns.
	ran := false
	ch := s.sfGroup.DoChan(key, func() (interface{}, error) {
		ran = true
		// Re-check storage inside singleflight worker in case another worker stored it while we waited
		if s.storage {
			if sbom, err := s.getSBOM(workerCtx, workload.ImageSlug, s.sbomCreator.Version()); err == nil && sbom.Content != nil {
				return sbomCreation{sbom: sbom}, nil
			}
		}

		if _, ok := s.tooManyRequests.Get(rateLimitCacheKey(workload)); ok {
			logger.L().Ctx(workerCtx).Warning("skipping SBOM creation, image pull previously rate limited",
				helpers.String("imageSlug", workload.ImageSlug))
			_ = s.platform.ReportScanFailure(workerCtx, scanfailure.ScanFailureSBOMGeneration,
				scanfailure.ReasonSBOMGenerationFailed, domain.ErrTooManyRequests)
			return domain.SBOM{}, &domain.ScanError{Reason: scanfailure.ReasonSBOMGenerationFailed, Err: domain.ErrTooManyRequests}
		}

		// create SBOM
		sbom, err := s.sbomCreator.CreateSBOM(workerCtx, workload.ImageSlug, workload.ImageHash, workload.ImageTagNormalized, opts)
		s.checkCreateSBOM(err, rateLimitCacheKey(workload))
		if err != nil {
			reason := classifySBOMError(err)
			_ = s.platform.ReportScanFailure(workerCtx, scanfailure.ScanFailureSBOMGeneration,
				reason, err)
			if s.storage &&
				workload.Wlid != "" &&
				workload.ContainerName != "" &&
				reason == scanfailure.ReasonImageSchemaUnsupported {
				if stubErr := s.cveRepository.StoreCVESummaryStub(workerCtx, helpersv1.UnsupportedSchema); stubErr != nil {
					logger.L().Ctx(workerCtx).Warning("storing schema-unsupported summary stub", helpers.Error(stubErr),
						helpers.String("imageSlug", workload.ImageSlug))
				}
			}
			return domain.SBOM{}, &domain.ScanError{Reason: reason, Err: err}
		}

		// store SBOM in storage before completing so all waiting callers share the stored
		// result.
		//
		// TooLarge is stored despite having no document. StoreSBOM keeps it as a status-only
		// marker, and getSBOM re-checks that marker against the current maxImageSize and
		// maxSBOMSize, so it stops applying once the limits are raised. Persisting it is what
		// saves pulling a known-oversized image again to reach the answer already on record.
		//
		// Incomplete is deliberately not stored. It means the scan timed out, which is
		// transient, and getSBOM has no staleness rule for it, so a stored one would read
		// back as a cache hit forever and block regeneration until the object was deleted by
		// hand or the scanner version moved.
		var storeErr error
		if s.storage && (sbom.Content != nil || sbom.Status == helpersv1.TooLarge) {
			if storeErr = s.sbomRepository.StoreSBOM(workerCtx, sbom, false); storeErr != nil {
				logger.L().Ctx(workerCtx).Warning("storing singleflight deduplicated SBOM", helpers.Error(storeErr),
					helpers.String("imageSlug", workload.ImageSlug))
			}
		}

		return sbomCreation{sbom: sbom, storeErr: storeErr}, nil
	})

	select {
	case res := <-ch:
		if res.Err != nil {
			return domain.SBOM{}, nil, res.Err
		}
		if !ran {
			metrics.RecordSingleflightHit(ctx, "sbom_generation")
		}
		created := res.Val.(sbomCreation)
		return created.sbom, created.storeErr, nil
	case <-ctx.Done():
		return domain.SBOM{}, nil, ctx.Err()
	}
}
