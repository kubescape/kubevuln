package v1

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"encoding/json"
	"io"

	"github.com/akyoto/cache"
	"github.com/armosec/armoapi-go/armotypes"
	cs "github.com/armosec/armoapi-go/containerscan"
	v1 "github.com/armosec/armoapi-go/containerscan/v1"
	"github.com/armosec/armoapi-go/identifiers"
	"github.com/armosec/armoapi-go/scanfailure"
	"github.com/armosec/utils-go/httputils"
	pkgcautils "github.com/armosec/utils-k8s-go/armometadata"
	wlidpkg "github.com/armosec/utils-k8s-go/wlid"
	"github.com/cenkalti/backoff/v5"
	"github.com/hashicorp/go-multierror"
	backendClientV1 "github.com/kubescape/backend/pkg/client/v1"
	sysreport "github.com/kubescape/backend/pkg/server/v1/systemreports"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/kubevuln/core/ports"
	"go.opentelemetry.io/otel"
)

type BackendAdapter struct {
	eventReceiverRestURL  string
	apiServerRestURL      string
	clusterConfig         pkgcautils.ClusterConfig
	getCVEExceptionsFunc  func(string, string, *identifiers.PortalDesignator, map[string]string) ([]armotypes.VulnerabilityExceptionPolicy, error)
	httpPostFunc          func(context.Context, httputils.IHttpClient, string, map[string]string, []byte, time.Duration) (*http.Response, error)
	sendStatusFunc        func(*backendClientV1.BaseReportSender, string, bool)
	accessKey             string
	securityExceptionRepo ports.SecurityExceptionRepository
	exceptionsCache       *cache.Cache
	httpClient            httputils.IHttpClient
}

var _ ports.Platform = (*BackendAdapter)(nil)

// exceptionsCacheCleaningInterval controls how often expired entries are swept from exceptionsCache.
// exceptionsCacheTTL bounds how stale a cached exceptions/CRD merge can be before the next scan
// re-fetches from the backend and cluster; exceptions rarely change within a scan burst, so this
// avoids a network + CRD round trip on every single container scan.
//
// exceptionsCache is process-local (see #528): each Kubevuln replica keeps its own copy, so a
// SecurityException change observed by one pod is not visible to the others until their own
// cache entries expire. 1m (rather than the 5m this used to be) bounds that cross-pod worst case
// to something closer to the underlying CRD-list cache's own 30s TTL
// (repositories/apiserver.go's securityExceptionListCacheTTL), while still avoiding a
// network+CRD round trip on every single container scan within a burst.
const (
	exceptionsCacheCleaningInterval = 1 * time.Minute
	exceptionsCacheTTL              = 1 * time.Minute
)

// cacheTTLFor bounds base by the earliest ExpirationDate among policies, so a cache entry
// containing a CRD-based exception never outlives that exception's own expiresAt. Without
// this, ConvertToVulnerabilityExceptionPolicies' expiry check only ever runs on a cache miss:
// an exception expiring mid-TTL would otherwise keep being served (and keep suppressing
// matching CVEs) from the stale cache entry until the fixed exceptionsCacheTTL elapsed,
// regardless of how soon it actually expired.
func cacheTTLFor(policies []armotypes.VulnerabilityExceptionPolicy, base time.Duration) time.Duration {
	ttl := base
	now := time.Now()
	for _, p := range policies {
		if p.ExpirationDate == nil {
			continue
		}
		if until := p.ExpirationDate.Sub(now); until < ttl {
			ttl = until
		}
	}
	if ttl < 0 {
		ttl = 0
	}
	return ttl
}

func NewBackendAdapter(accountID, apiServerRestURL, eventReceiverRestURL, accessKey string, seRepo ports.SecurityExceptionRepository) *BackendAdapter {
	return &BackendAdapter{
		clusterConfig: pkgcautils.ClusterConfig{
			AccountID: accountID,
		},
		eventReceiverRestURL: eventReceiverRestURL,
		apiServerRestURL:     apiServerRestURL,
		getCVEExceptionsFunc: backendClientV1.GetCVEExceptionByDesignator,
		httpPostFunc:         httpPostWithContext,
		sendStatusFunc: func(sender *backendClientV1.BaseReportSender, status string, sendReport bool) {
			sender.SendStatus(status, sendReport) // TODO - update this function to use from kubescape/backend
		},
		accessKey:             accessKey,
		securityExceptionRepo: seRepo,
		exceptionsCache:       cache.New(exceptionsCacheCleaningInterval),
		httpClient: &http.Client{
			Timeout: 60 * time.Second,
			Transport: &http.Transport{
				Proxy:               http.ProxyFromEnvironment,
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 32,
				IdleConnTimeout:     90 * time.Second,
			},
		},
	}
}

func (a *BackendAdapter) getHTTPClient() httputils.IHttpClient {
	if a.httpClient != nil {
		return a.httpClient
	}
	return http.DefaultClient
}

// httpPostWithContext is the default httpPostFunc. Unlike httputils.HttpPostWithRetry (which
// binds context.Background() to the request and retries on a plain, non-cancellable
// backoff.Retry loop), it threads the caller's ctx through the request AND the retry loop, so
// cancelling ctx aborts both an in-flight attempt and any further retries promptly instead of
// running the full retry budget to completion regardless of cancellation (#446).
func httpPostWithContext(ctx context.Context, httpClient httputils.IHttpClient, fullURL string, headers map[string]string, body []byte, maxElapsedTime time.Duration) (*http.Response, error) {
	bo := backoff.NewExponentialBackOff()
	return backoff.Retry(ctx, func() (*http.Response, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, fullURL, bytes.NewReader(body))
		if err != nil {
			return nil, backoff.Permanent(err)
		}
		for k, v := range headers {
			req.Header.Set(k, v)
		}

		resp, err := httpClient.Do(req)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusOK {
			defer resp.Body.Close()
			bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
			bodyStr := strings.TrimSpace(string(bodyBytes))
			var retryErr error
			if bodyStr != "" {
				retryErr = fmt.Errorf("received status code: %d, body: %s", resp.StatusCode, bodyStr)
			} else {
				retryErr = fmt.Errorf("received status code: %d", resp.StatusCode)
			}
			if !shouldRetryReport(resp) {
				return nil, backoff.Permanent(retryErr)
			}
			if wait, ok := parseRetryAfter(resp); ok {
				if wait > 0 {
					wait = wait.Round(time.Second)
					if wait == 0 {
						wait = time.Second
					}
				}
				return nil, backoff.RetryAfter(int(wait.Seconds()))
			}
			return nil, retryErr
		}
		return resp, nil
	}, backoff.WithBackOff(bo), backoff.WithMaxElapsedTime(maxElapsedTime))
}

// parseRetryAfter reads the standard Retry-After header from resp, in either of its two
// legitimate forms (RFC 9110 10.2.3): a plain non-negative number of seconds, or an
// HTTP-date. Returns ok=false if the header is absent, empty, negative, or in neither
// recognized form. A parsed date that has already passed is treated as "no wait" (zero
// duration), not a negative one.
func parseRetryAfter(resp *http.Response) (time.Duration, bool) {
	v := resp.Header.Get("Retry-After")
	if v == "" {
		return 0, false
	}
	if seconds, err := strconv.ParseInt(v, 10, 64); err == nil {
		const maxRetryAfterSeconds = math.MaxInt64 / int64(time.Second)
		if seconds < 0 || seconds > maxRetryAfterSeconds {
			return 0, false
		}
		return time.Duration(seconds) * time.Second, true
	}
	if t, err := http.ParseTime(v); err == nil {
		wait := time.Until(t)
		if wait < 0 {
			wait = 0
		}
		return wait, true
	}
	return 0, false
}

// shouldRetryReport is derived from the unexported defaultShouldRetry in armosec/utils-go, but
// intentionally diverges from it: upstream treats 500 as fatal, we retry it. A 500 from the event
// receiver is usually transient (gateway blip, backend pod restart), so dropping the scan result
// on the first one loses data that a retry would have delivered (#486). The retry budget is
// bounded by maxElapsedTime, so a genuinely broken backend still fails fast enough.
func shouldRetryReport(resp *http.Response) bool {
	return resp.StatusCode != http.StatusUnauthorized &&
		resp.StatusCode != http.StatusForbidden &&
		resp.StatusCode != http.StatusNotFound
}

const ActionName = "vuln scan"
const ReporterName = "ca-vuln-scan"
const maxBodySize int = 30000

var details = []string{
	"Inqueueing",
	"Dequeueing",
	"Dequeueing",
	"Dequeueing",
}
var statuses = []string{
	sysreport.JobStarted,
	sysreport.JobStarted,
	sysreport.JobSuccess,
	sysreport.JobDone,
}

func (a *BackendAdapter) GetCVEExceptions(ctx context.Context) (domain.CVEExceptions, domain.ExceptionStats, error) {
	ctx, span := otel.Tracer("").Start(ctx, "BackendAdapter.GetCVEExceptions")
	defer span.End()

	// retrieve workload from context
	workload, ok := ctx.Value(domain.WorkloadKey{}).(domain.ScanCommand)
	if !ok {
		return nil, domain.ExceptionStats{}, domain.ErrCastingWorkload
	}

	namespace := wlidpkg.GetNamespaceFromWlid(workload.Wlid)
	// Registry scans carry no Wlid (registryScanCommandToScanCommand never sets
	// it), which would otherwise collapse every scanned image onto the same
	// cache key ("<accountID>/////"). Skip caching entirely for them rather than
	// let unrelated images share exceptions.
	cacheable := workload.Wlid != ""
	cacheKey := strings.Join([]string{
		a.clusterConfig.AccountID,
		wlidpkg.GetClusterFromWlid(workload.Wlid),
		namespace,
		strings.ToLower(wlidpkg.GetKindFromWlid(workload.Wlid)),
		wlidpkg.GetNameFromWlid(workload.Wlid),
		workload.ContainerName,
		workload.ImageTagNormalized,
	}, "/")

	if cacheable && a.exceptionsCache != nil {
		if cached, ok := a.exceptionsCache.Get(cacheKey); ok {
			// A cache hit skips CRD re-evaluation entirely, so there is nothing new to
			// report this call; the zero value is correct, not a missing measurement.
			return cached.(domain.CVEExceptions), domain.ExceptionStats{}, nil
		}
	}

	designator := identifiers.PortalDesignator{
		DesignatorType: identifiers.DesignatorAttribute,
		Attributes: map[string]string{
			"customerGUID":        a.clusterConfig.AccountID,
			"scope.cluster":       wlidpkg.GetClusterFromWlid(workload.Wlid),
			"scope.namespace":     namespace,
			"scope.kind":          strings.ToLower(wlidpkg.GetKindFromWlid(workload.Wlid)),
			"scope.name":          wlidpkg.GetNameFromWlid(workload.Wlid),
			"scope.containerName": workload.ContainerName,
		},
	}

	vulnExceptionList, err := a.getCVEExceptionsFunc(a.apiServerRestURL, a.clusterConfig.AccountID, &designator, a.getRequestHeaders())
	if err != nil {
		return nil, domain.ExceptionStats{}, err
	}

	// Merge CRD-based exceptions
	degraded := false
	stats := domain.ExceptionStats{}
	seList, cseList, crdErr := a.securityExceptionRepo.GetSecurityExceptions(ctx, namespace)
	if crdErr != nil {
		logger.L().Ctx(ctx).Warning("failed to get CRD security exceptions", helpers.Error(crdErr))
		// Best-effort degradation that self-heals on the next scan. The set is
		// incomplete: caching it would suppress valid CRD exceptions for the full
		// TTL, and callers must not persist "removals" computed from it.
		cacheable = false
		degraded = true
	}
	if len(seList) > 0 || len(cseList) > 0 {
		target := BuildExceptionTarget(ctx, workload, seList, cseList, a.securityExceptionRepo)
		crdPolicies, crdStats := ConvertToVulnerabilityExceptionPolicies(seList, cseList, target)
		vulnExceptionList = append(vulnExceptionList, crdPolicies...)
		stats = crdStats

		// A selector-based exception whose labels failed to resolve fails closed
		// (see matchExceptionTarget), which is also a self-healing degradation and
		// must not be cached as if it were the authoritative result.
		if (UsesObjectSelector(seList, cseList) && !target.WorkloadLabelsResolved) ||
			(UsesNamespaceSelector(cseList) && !target.NamespaceLabelsResolved) {
			cacheable = false
			degraded = true
		}
	}

	// A non-positive TTL means a policy has already expired by the time we're about to
	// cache it (e.g. lost a race with its own expiresAt between conversion and this
	// point). akyoto/cache only reaps entries on its cleaning-interval sweep, not the
	// instant their TTL elapses, so a Set with ttl<=0 would still be readable as a cache
	// hit until the next sweep -- skip the write entirely rather than rely on that.
	if ttl := cacheTTLFor(vulnExceptionList, exceptionsCacheTTL); cacheable && a.exceptionsCache != nil && ttl > 0 {
		a.exceptionsCache.Set(cacheKey, domain.CVEExceptions(vulnExceptionList), ttl)
	}

	if degraded {
		return vulnExceptionList, stats, domain.ErrExceptionsDegraded
	}

	return vulnExceptionList, stats, nil
}

// ReportError reports the given error to the platform
func (a *BackendAdapter) ReportError(ctx context.Context, err error) error {
	ctx, span := otel.Tracer("").Start(ctx, "BackendAdapter.ReportError")
	defer span.End()

	if err == nil {
		return nil
	}

	if err := ctx.Err(); err != nil {
		return err
	}

	report, err2 := a.reportFromContext(ctx)
	if err2 != nil {
		return err2
	}
	report.Details = fmt.Sprintf("Error: %s", err.Error())
	report.Errors = append(report.Errors, err.Error())
	report.Status = sysreport.JobFailed

	// NOTE: unlike postResults/ReportScanFailure, this call is not ctx-cancellation-aware.
	// backendClientV1.NewBaseReportSender builds its own *http.Request bound to
	// context.Background() inside armosec/utils-go, before it ever reaches our IHttpClient, so
	// there's no seam here to inject ctx without either bypassing the sender or a ctx-accepting
	// constructor upstream in kubescape/backend. Tracked separately (#450) rather than silently
	// left unaddressed.
	sender := backendClientV1.NewBaseReportSender(a.eventReceiverRestURL, a.getHTTPClient(), a.getRequestHeaders(), report)
	a.sendStatusFunc(sender, sysreport.JobFailed, true)
	return nil
}

// ReportScanFailure sends a structured ScanFailureReport to the backend.
// reason is a human-friendly constant (from scanfailure.Reason*) displayed in notifications.
// scanErr is the raw error for R&D debugging (stored in the Error field, not shown to users).
func (a *BackendAdapter) ReportScanFailure(ctx context.Context, failureCase scanfailure.ScanFailureCase, reason string, scanErr error) error {
	ctx, span := otel.Tracer("").Start(ctx, "BackendAdapter.ReportScanFailure")
	defer span.End()

	workload, ok := ctx.Value(domain.WorkloadKey{}).(domain.ScanCommand)
	if !ok {
		return domain.ErrCastingWorkload
	}

	report := scanfailure.ScanFailureReport{
		CustomerGUID:  a.clusterConfig.AccountID,
		ImageTag:      workload.ImageTagNormalized,
		ImageHash:     workload.ImageHash,
		JobID:         workload.JobID,
		FailureCase:   failureCase,
		FailureReason: reason,
		Timestamp:     time.Now(),
		Workloads: []scanfailure.WorkloadIdentifier{{
			ClusterName:   wlidpkg.GetClusterFromWlid(workload.Wlid),
			Namespace:     wlidpkg.GetNamespaceFromWlid(workload.Wlid),
			WorkloadKind:  wlidpkg.GetKindFromWlid(workload.Wlid),
			WorkloadName:  wlidpkg.GetNameFromWlid(workload.Wlid),
			ContainerName: workload.ContainerName,
		}},
	}

	if scanErr != nil {
		report.Error = scanErr.Error()
	}

	// For registry scans, populate registry fields instead of workload
	if regName, ok := workload.Args[identifiers.AttributeRegistryName]; ok {
		if name, ok := regName.(string); ok {
			report.IsRegistryScan = true
			report.RegistryName = name
			report.Workloads = nil
		}
	}

	payload, err := json.Marshal(report)
	if err != nil {
		return fmt.Errorf("marshal scan failure report: %w", err)
	}

	url := fmt.Sprintf("%s/k8s/v2/scanFailure", a.eventReceiverRestURL)
	resp, err := a.httpPostFunc(ctx, a.getHTTPClient(), url, a.getRequestHeaders(), payload, 30*time.Second)
	if err != nil {
		logger.L().Ctx(ctx).Warning("failed to send scan failure report",
			helpers.Error(err),
			helpers.String("failureCase", failureCase.String()),
			helpers.String("reason", reason))
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode >= http.StatusBadRequest {
		return fmt.Errorf("scan failure report returned HTTP %d", resp.StatusCode)
	}
	return nil
}

// SendStatus sends the given status and details to the platform
func (a *BackendAdapter) SendStatus(ctx context.Context, step int) error {
	ctx, span := otel.Tracer("").Start(ctx, "BackendAdapter.SendStatus")
	defer span.End()

	if err := ctx.Err(); err != nil {
		return err
	}

	report, err := a.reportFromContext(ctx)
	if err != nil {
		return err
	}
	report.Details = details[step]
	report.Status = statuses[step]

	// NOTE: see the same comment on ReportError above — this call has the same ctx-cancellation
	// gap for the same reason.
	sender := backendClientV1.NewBaseReportSender(a.eventReceiverRestURL, a.getHTTPClient(), a.getRequestHeaders(), report)
	a.sendStatusFunc(sender, statuses[step], true)
	return nil
}

func (a *BackendAdapter) reportFromContext(ctx context.Context) (*sysreport.BaseReport, error) {
	// retrieve workload from context
	workload, ok := ctx.Value(domain.WorkloadKey{}).(domain.ScanCommand)
	if !ok {
		return nil, domain.ErrCastingWorkload
	}

	lastAction := workload.LastAction + 1
	report := sysreport.NewBaseReport(
		a.clusterConfig.AccountID,
		ReporterName,
	)
	report.Target = fmt.Sprintf("vuln scan:: scanning wlid: %v , container: %v imageTag: %v imageHash: %s",
		workload.Wlid, workload.ContainerName, workload.ImageTagNormalized, workload.ImageHash)
	report.ActionID = strconv.Itoa(lastAction)
	report.ActionIDN = lastAction
	report.ActionName = ActionName
	report.JobID = workload.JobID
	report.ParentAction = workload.ParentJobID
	report.Timestamp = time.Now()
	return report, nil
}

// SubmitCVE submits the given CVE to the platform
func (a *BackendAdapter) SubmitCVE(ctx context.Context, cve domain.CVEManifest, cvep domain.CVEManifest) error {
	ctx, span := otel.Tracer("").Start(ctx, "BackendAdapter.SubmitCVE")
	defer span.End()
	// retrieve timestamp from context
	timestamp, ok := ctx.Value(domain.TimestampKey{}).(int64)
	if !ok {
		return domain.ErrMissingTimestamp
	}
	// retrieve scanID from context
	scanID, ok := ctx.Value(domain.ScanIDKey{}).(string)
	if !ok {
		return domain.ErrMissingScanID
	}
	// retrieve workload from context
	workload, ok := ctx.Value(domain.WorkloadKey{}).(domain.ScanCommand)
	if !ok {
		return domain.ErrCastingWorkload
	}

	// validate one more time the scanID before sending it to the platform
	if !armotypes.ValidateContainerScanID(scanID) {
		return domain.ErrInvalidScanID
	}

	// get exceptions
	exceptions, _, err := a.GetCVEExceptions(ctx)
	if err != nil && !errors.Is(err, domain.ErrExceptionsDegraded) {
		return fmt.Errorf("failed to get exceptions: %w", err)
	}
	// convert to vulnerabilities
	vulnerabilities, err := DomainToArmo(ctx, *cve.Content, exceptions)
	if err != nil {
		return fmt.Errorf("failed to convert vulnerabilities to report: %w", err)
	}

	imageManifest, e := ParseImageManifest(cve.Content)
	if e != nil {
		logger.L().Ctx(ctx).Warning("failed to parse image manifest from grype document", helpers.Error(e))
	}

	// merge cve and cvep
	var hasRelevancy bool
	if cvep.Content != nil {
		hasRelevancy = true
		// convert to relevantVulnerabilities
		relevantVulnerabilities, err := DomainToArmo(ctx, *cvep.Content, exceptions)
		if err != nil {
			return fmt.Errorf("failed to convert filtered vulnerabilities to report: %w", err)
		}
		// mark common vulnerabilities as relevant
		markRelevantVulnerabilities(vulnerabilities, relevantVulnerabilities)
	}

	finalReport := v1.ScanResultReport{
		Designators:     *identifiers.AttributesDesignatorsFromWLID(workload.Wlid),
		Summary:         nil,
		ContainerScanID: scanID,
		Timestamp:       timestamp,
	}

	// fill designators
	finalReport.Designators.Attributes[identifiers.AttributeContainerName] = workload.ContainerName
	finalReport.Designators.Attributes[identifiers.AttributeWorkloadHash] = cs.GenerateWorkloadHash(finalReport.Designators.Attributes)
	finalReport.Designators.Attributes[identifiers.AttributeCustomerGUID] = a.clusterConfig.AccountID

	finalReport.Designators.Attributes[identifiers.AttributeSBOMToolVersion] = cve.SBOMCreatorVersion
	finalReport.Designators.Attributes[identifiers.AttributeSBOMToolName] = cve.SBOMCreatorName

	if val, ok := workload.Args[identifiers.AttributeRegistryName].(string); ok {
		finalReport.Designators.Attributes[identifiers.AttributeRegistryName] = val
	}
	if val, ok := workload.Args[identifiers.AttributeRepository].(string); ok {
		finalReport.Designators.Attributes[identifiers.AttributeRepository] = val
	}
	if val, ok := workload.Args[identifiers.AttributeTag].(string); ok {
		finalReport.Designators.Attributes[identifiers.AttributeTag] = val
	}
	if val, ok := workload.Args[identifiers.AttributeSensor].(string); ok {
		finalReport.Designators.Attributes[identifiers.AttributeSensor] = val
	}
	if val, ok := workload.Args[identifiers.AttributeRegistryID].(string); ok {
		finalReport.Designators.Attributes[identifiers.AttributeRegistryID] = val
	}
	if val, ok := workload.Args[identifiers.AttributeRegistryScanID].(string); ok {
		finalReport.Designators.Attributes[identifiers.AttributeRegistryScanID] = val
	}
	if val, ok := workload.Args[identifiers.AttributeRegistryScanImagesCount].(string); ok {
		finalReport.Designators.Attributes[identifiers.AttributeRegistryScanImagesCount] = val
	}
	if val, ok := finalReport.Designators.Attributes[identifiers.AttributeKind]; ok {
		if s, err := k8sinterface.GetGroupVersionResource(val); err == nil {
			finalReport.Designators.Attributes[identifiers.AttributeApiVersion] = k8sinterface.JoinGroupVersion(s.Group, s.Version)
		}
	}
	// fill context and designators into vulnerabilities
	armoContext := identifiers.DesignatorToArmoContext(&finalReport.Designators, "designators")
	for i := range vulnerabilities {
		vulnerabilities[i].Context = armoContext
		vulnerabilities[i].Designators = finalReport.Designators
	}

	// add summary
	finalReport.Summary, vulnerabilities = Summarize(finalReport, vulnerabilities, workload, hasRelevancy, imageManifest)
	finalReport.Summary.Context = armoContext

	// split vulnerabilities to chunks
	chunksChan, totalVulnerabilities := httputils.SplitSlice2Chunks(vulnerabilities, maxBodySize, 10)

	// send report(s)
	sendWG := &sync.WaitGroup{}
	errChan := make(chan error, 10)
	// get the first chunk
	firstVulnerabilitiesChunk := <-chunksChan
	firstChunkVulnerabilitiesCount := len(firstVulnerabilitiesChunk)
	// send the summary and the first chunk in one or two reports according to the size
	nextPartNum, summaryErr := a.sendSummaryAndVulnerabilities(ctx, &finalReport, a.eventReceiverRestURL, totalVulnerabilities, scanID, firstVulnerabilitiesChunk, errChan, sendWG)
	if summaryErr != nil {
		// Nothing was sent, so no chunk goroutine was dispatched and nothing will ever drain
		// chunksChan or close errChan on its own. Drain chunksChan ourselves so the producer
		// goroutine started by SplitSlice2Chunks doesn't block forever trying to hand off the
		// remaining chunks (#446), and return directly instead of ranging over an errChan
		// nothing will close.
		go func() {
			for range chunksChan {
			}
		}()
		return summaryErr
	}
	// if not all vulnerabilities got into the first chunk
	if totalVulnerabilities != firstChunkVulnerabilitiesCount {
		//send the rest of the vulnerabilities - error channel will be closed when all vulnerabilities are sent
		a.sendVulnerabilitiesRoutine(ctx, chunksChan, a.eventReceiverRestURL, scanID, finalReport, errChan, sendWG, totalVulnerabilities, firstChunkVulnerabilitiesCount, nextPartNum)
	} else {
		//only one chunk will be sent so need to close the error channel when it is done
		go func(wg *sync.WaitGroup, errorChan chan error) {
			//wait for summary post request to end
			wg.Wait()
			//close the error channel
			close(errorChan)
		}(sendWG, errChan)
	}

	// collect post report errors if occurred
	for e := range errChan {
		err = multierror.Append(err, e)
	}
	return err
}

//lint:ignore U1000 Ignore unused function temporarily for debugging
func httpPostDebug(httpClient httputils.IHttpClient, fullURL string, headers map[string]string, body []byte) (*http.Response, error) {
	logger.L().Debug("httpPostDebug", helpers.String("fullURL", fullURL), helpers.Interface("headers", headers), helpers.String("body", string(body)))
	return httputils.HttpPostWithContext(context.Background(), httpClient, fullURL, headers, body, -1, func(resp *http.Response) bool { return true })
}

// relevancyIdentity is what makes two vulnerability records the same finding: the CVE, and
// the package it was found on. The package needs its version as well as its name, because a
// name is not unique within an image. Two versions of one library can sit side by side, which
// is ordinary in Java and Node images, and DomainToArmo emits a record per (vulnerability,
// artifact) pair, so both versions produce a record carrying the same name.
type relevancyIdentity struct {
	cve            string
	packageName    string
	packageVersion string
}

func identifyForRelevancy(v cs.CommonContainerVulnerabilityResult) relevancyIdentity {
	return relevancyIdentity{cve: v.Name, packageName: v.RelatedPackageName, packageVersion: v.PackageVersion}
}

// markRelevantVulnerabilities annotates each vulnerability with IsRelevant=true iff the same
// finding also appeared in the relevancy (CVEp) scan. Keying by CVE id alone would mark a CVE
// relevant on every package it affects even when only one of those packages was executed, and
// keying by CVE and package name alone does the same thing one level down, marking an
// unloaded version of a library relevant because another version of it was loaded. Both
// manifests are built from the same artifacts, the filtered one from a subset of the same
// SBOM, so the versions on either side are the same strings.
func markRelevantVulnerabilities(vulnerabilities, relevantVulnerabilities []cs.CommonContainerVulnerabilityResult) {
	cvepIndices := make(map[relevancyIdentity]struct{}, len(relevantVulnerabilities))
	for _, v := range relevantVulnerabilities {
		cvepIndices[identifyForRelevancy(v)] = struct{}{}
	}
	for i, v := range vulnerabilities {
		_, isRelevant := cvepIndices[identifyForRelevancy(v)]
		vulnerabilities[i].IsRelevant = &isRelevant
	}
}
