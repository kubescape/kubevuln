package controllers

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	wssc "github.com/armosec/armoapi-go/apis"
	"github.com/armosec/armoapi-go/scanfailure"
	"github.com/gammazero/workerpool"
	"github.com/gin-gonic/gin"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/names"
	v1 "github.com/kubescape/kubevuln/adapters/v1"
	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/kubevuln/core/ports"
	"github.com/kubescape/kubevuln/internal/metrics"
	"github.com/kubescape/kubevuln/internal/tools"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"schneider.vip/problem"
)

// HTTPController maps ScanService ports to gin handlers that can be mapped to paths and methods
// this mapping is usually done in main()
type HTTPController struct {
	scanService  ports.ScanService
	workerPool   *workerpool.WorkerPool
	metrics      *metrics.Metrics
	diagnostics  func(ctx context.Context) domain.Diagnostics
	statuses     *scanStatusStore
	statusesOnce sync.Once

	// submitGate and shuttingDown guard workerPool.Submit against Shutdown's
	// workerPool.Stop(), which closes the pool's task channel: submitting to a closed
	// channel panics, and nothing about admitQueueSlot/tryAdmit above prevents a handler
	// from still being between admission and Submit when shutdown begins (#758). submit()
	// holds submitGate for read while it checks shuttingDown and calls Submit; Shutdown
	// takes submitGate for write to set shuttingDown, which can only complete once every
	// in-flight submit() call has released its read lock -- so by the time Shutdown moves
	// on to workerPool.Stop(), either a given submit() call already finished handing its
	// task to the (still open) pool, or it will see shuttingDown and never touch the pool
	// at all. There is no interleaving where a submit() reaches the pool after Stop().
	submitGate   sync.RWMutex
	shuttingDown bool
	// submitBeforeHook, if set, is called synchronously by submit() once it has confirmed
	// shutdown hasn't started but before it hands the task to the pool. Tests use it as a
	// deterministic barrier to prove Shutdown really does wait for this window to close
	// before calling workerPool.Stop(), instead of a timing-based sleep.
	submitBeforeHook func()

	// maxQueueDepth bounds the number of scans tryAdmit will let through; see
	// WithMaxQueueDepth. Zero (the default) or a negative value means unbounded.
	maxQueueDepth int
	// pending counts scans currently accepted but not yet finished (queued or running),
	// guarded against maxQueueDepth by tryAdmit/release below. Unused when maxQueueDepth
	// is zero. int64, not int32: comparing against int64(h.maxQueueDepth) instead of
	// narrowing maxQueueDepth into an int32 avoids the wraparound a large configured
	// value would otherwise cause on a 64-bit build (int is 64 bits there).
	pending atomic.Int64
}

// NewHTTPController initializes the HTTPController struct with the injected scanService
func NewHTTPController(scanService ports.ScanService, concurrency int) *HTTPController {
	return &HTTPController{
		scanService: scanService,
		workerPool:  workerpool.New(concurrency),
		statuses:    newScanStatusStore(),
	}
}

// WithMetrics attaches an OTel-backed metrics recorder to the controller, enabling
// per-endpoint scan counters/durations, rejection counts, and a worker-pool queue
// depth gauge. It is a no-op to call the handlers without this having been set.
func (h *HTTPController) WithMetrics(m *metrics.Metrics) (*HTTPController, error) {
	h.metrics = m

	_, err := m.Meter().Int64ObservableGauge(
		"kubevuln_worker_pool_queue_depth",
		metric.WithDescription("Number of scan jobs currently waiting in the HTTP controller's worker pool"),
		metric.WithInt64Callback(func(_ context.Context, o metric.Int64Observer) error {
			o.Observe(int64(h.workerPool.WaitingQueueSize()))
			return nil
		}),
	)
	if err != nil {
		return h, err
	}
	return h, nil
}

// WithDiagnostics attaches the callback the Diagnostics handler uses to report the
// scan mode and backend versions currently in effect. A callback (rather than a
// fixed value) is required because the CVE DB version changes as the background
// updater in GrypeAdapter refreshes it (see adapters/v1/grype.go). It is a no-op to
// call the handler without this having been set, returning the struct's zero value.
func (h *HTTPController) WithDiagnostics(f func(ctx context.Context) domain.Diagnostics) *HTTPController {
	h.diagnostics = f
	return h
}

// WithMaxQueueDepth bounds the number of scans this controller will accept but not yet
// finish (queued or running) to n. workerpool.Submit never blocks and its waiting queue is
// unbounded regardless of scanConcurrency, so without an admission check here a sustained
// burst of requests grows the backlog -- and the registry credentials each queued job's
// closure holds onto -- without limit (see #748). Once at capacity, new scan requests are
// rejected with a 503 (domain.ErrQueueFull) instead of being queued.
//
// n <= 0, including never calling this (the struct's zero value), means unbounded, preserving
// the pre-existing behavior for anyone who doesn't opt in.
func (h *HTTPController) WithMaxQueueDepth(n int) *HTTPController {
	h.maxQueueDepth = n
	return h
}

// tryAdmit atomically reserves one slot of the controller's admission budget, returning false
// without side effects if maxQueueDepth is already reached. Every caller that receives true
// owns exactly one matching release() call once that job's outcome (success or failure) is
// recorded -- for GenerateSBOM/ScanCVE/ScanRegistry that's runTrackedScan's worker closure
// returning; ScanCP's own copy of that closure does the same. Always true when maxQueueDepth
// is unbounded (<= 0), which also skips touching pending, so the unbounded default carries no
// extra synchronization cost over the pre-#748 behavior.
func (h *HTTPController) tryAdmit() bool {
	if h.maxQueueDepth <= 0 {
		return true
	}
	limit := int64(h.maxQueueDepth)
	for {
		current := h.pending.Load()
		if current >= limit {
			return false
		}
		if h.pending.CompareAndSwap(current, current+1) {
			return true
		}
	}
}

// release returns one slot of admission budget reserved by a prior successful tryAdmit call.
// A no-op when maxQueueDepth is unbounded, matching tryAdmit never having reserved anything in
// that case.
func (h *HTTPController) release() {
	if h.maxQueueDepth <= 0 {
		return
	}
	h.pending.Add(-1)
}

// admitQueueSlot reserves one slot of admission budget for endpoint via tryAdmit. If the
// controller is at capacity, it writes the 503/ErrQueueFull rejection response to c itself
// (mirroring the ErrTooManyRequests handling each handler already does for its own validation
// errors) and returns false; the caller must stop processing the request without reserving a
// slot. On true, the caller owns exactly one release() call once the accepted job's outcome is
// recorded.
func (h *HTTPController) admitQueueSlot(c *gin.Context, ctx context.Context, endpoint string, details problem.Option) bool {
	if h.tryAdmit() {
		return true
	}
	logger.L().Ctx(ctx).Warning("rejecting scan, queue is full",
		helpers.String("endpoint", endpoint),
		helpers.Int("maxQueueDepth", h.maxQueueDepth))
	h.recordRejection(ctx, endpoint, domain.ErrQueueFull)
	_, _ = problem.Of(validationStatusCode(domain.ErrQueueFull)).Append(details).WriteTo(c.Writer)
	return false
}

// admitJob reserves a queue slot for endpoint via admitQueueSlot and then records jobID as
// newly accepted via recordAccepted, rejecting a jobID that already belongs to an active
// (queued or running) job instead of silently resetting its tracking record out from under
// it (see #856). On success it writes the 200 OK response the caller uses to start polling
// ScanStatus and returns true. On failure -- the queue is full, or jobID collides with an
// active job -- it writes the appropriate rejection response itself, releases any queue slot
// it reserved, and returns false; either way the caller must stop processing the request
// without doing anything else.
//
// The isActive check runs before admitQueueSlot on purpose: without it, a jobID that
// collides with the very job occupying the controller's last admission slot would be
// rejected as queue-full (503) before recordAccepted ever got a chance to diagnose it as a
// duplicate (409), since admission capacity would already be exhausted by the time
// recordAccepted ran. It's a precedence check only -- recordAccepted's own atomic
// check-and-write remains the actual guard against a genuine race between two admissions
// for the same jobID, so a duplicate that slips past this read-only check is still caught
// there.
func (h *HTTPController) admitJob(c *gin.Context, ctx context.Context, endpoint, jobID string, details problem.Option) bool {
	if h.ensureStatuses().isActive(jobID) {
		h.rejectDuplicateJobID(c, ctx, endpoint, jobID, details)
		return false
	}
	if !h.admitQueueSlot(c, ctx, endpoint, details) {
		return false
	}
	if !h.ensureStatuses().recordAccepted(jobID, endpoint) {
		h.release()
		h.rejectDuplicateJobID(c, ctx, endpoint, jobID, details)
		return false
	}
	_, _ = problem.Of(http.StatusOK).Append(details).WriteTo(c.Writer)
	return true
}

// rejectDuplicateJobID writes the 409/ErrDuplicateJobID rejection response for jobID and
// records it, shared by admitJob's two rejection points (the isActive precedence check and
// the recordAccepted race fallback).
func (h *HTTPController) rejectDuplicateJobID(c *gin.Context, ctx context.Context, endpoint, jobID string, details problem.Option) {
	logger.L().Ctx(ctx).Warning("rejecting scan, jobID already has an active scan in progress",
		helpers.String("endpoint", endpoint),
		helpers.String("jobID", jobID))
	h.recordRejection(ctx, endpoint, domain.ErrDuplicateJobID)
	_, _ = problem.Of(validationStatusCode(domain.ErrDuplicateJobID)).Append(details).WriteTo(c.Writer)
}

// submit hands task to the worker pool, unless Shutdown has already begun, in which case
// it returns false without touching the pool at all. Callers must treat false the same as
// a lost race with shutdown: release the admission slot task's defer h.release() will now
// never run to release, and mark the job abandoned instead of leaving it stuck "accepted"
// forever, since its 200 OK response was already written before this call (see #758).
func (h *HTTPController) submit(task func()) bool {
	h.submitGate.RLock()
	defer h.submitGate.RUnlock()
	if h.shuttingDown {
		return false
	}
	if h.submitBeforeHook != nil {
		h.submitBeforeHook()
	}
	h.workerPool.Submit(task)
	return true
}

func (h *HTTPController) ensureStatuses() *scanStatusStore {
	h.statusesOnce.Do(func() {
		if h.statuses == nil {
			h.statuses = newScanStatusStore()
		}
	})
	return h.statuses
}

func (h *HTTPController) claimTrackedJob(jobID string) bool {
	if jobID == "" {
		return true
	}
	return h.ensureStatuses().markRunning(jobID)
}

// recordScan records the outcome and duration of a background scan job for the given endpoint.
// outcome is one of "success", "partial", or "error" -- see the ScanCP call site, where a
// domain.ErrPartialContainerProfile result is a warning-level expected outcome, not a failure.
// err is the error returned by the scan (nil for success/partial) and is only consulted to
// resolve the bounded reason label on a failed outcome; see scanFailureReason.
func (h *HTTPController) recordScan(ctx context.Context, endpoint string, start time.Time, outcome string, err error) {
	if h.metrics == nil {
		return
	}
	attrs := metric.WithAttributes(
		attribute.String("endpoint", endpoint),
		attribute.String("outcome", outcome),
		attribute.String("reason", scanFailureReason(outcome, err)),
	)
	h.metrics.ScanCounter.Add(ctx, 1, attrs)
	h.metrics.ScanDuration.Record(ctx, time.Since(start).Seconds(), attrs)
}

// scanFailureReason resolves the bounded scanfailure.Reason* label for a scan-outcome metric.
// Successful/partial outcomes carry no specific failure reason ("none"). A failed outcome whose
// error was classified via *domain.ScanError (set at the point of failure in
// core/services/scan.go, alongside the equivalent ReportScanFailure call to the platform)
// surfaces that reason; any other error defaults to scanfailure.ReasonUnexpected, keeping the
// label's cardinality fixed regardless of what an unclassified error's message happens to say.
func scanFailureReason(outcome string, err error) string {
	if outcome != "error" {
		return "none"
	}
	var scanErr *domain.ScanError
	if errors.As(err, &scanErr) && scanErr.Reason != "" {
		return scanErr.Reason
	}
	return scanfailure.ReasonUnexpected
}

// recordRejection records a validation-time rejection for the given endpoint. reason is
// "too_many_requests" for registry back-pressure (ErrTooManyRequests), "queue_full" for local
// admission control (ErrQueueFull, see WithMaxQueueDepth), "duplicate_job_id" for a jobID
// that already belongs to an active job (ErrDuplicateJobID, see admitJob), and
// "invalid_request" for every other validation error, keeping the rejection-rate signal
// distinct from malformed-payload noise while staying low cardinality.
func (h *HTTPController) recordRejection(ctx context.Context, endpoint string, err error) {
	if h.metrics == nil {
		return
	}
	reason := "invalid_request"
	switch {
	case errors.Is(err, domain.ErrTooManyRequests):
		reason = "too_many_requests"
	case errors.Is(err, domain.ErrQueueFull):
		reason = "queue_full"
	case errors.Is(err, domain.ErrDuplicateJobID):
		reason = "duplicate_job_id"
	}
	h.metrics.RejectCounter.Add(ctx, 1, metric.WithAttributes(
		attribute.String("endpoint", endpoint),
		attribute.String("reason", reason),
	))
}

// bindScanCommand decodes the request body into T and converts it to a domain.ScanCommand.
// A body that will not bind is answered here with the same 400 each handler used to write
// for itself, and reported as ok=false so the caller returns without scanning. T is the
// wire command the endpoint accepts, which is WebsocketScanCommand for three of the four
// and RegistryScanCommand for ScanRegistry.
func bindScanCommand[T any](c *gin.Context, ctx context.Context, convert func(T) domain.ScanCommand) (domain.ScanCommand, bool) {
	var cmd T
	if err := c.ShouldBindJSON(&cmd); err != nil {
		logger.L().Ctx(ctx).Error("handler error", helpers.Error(err))
		_, _ = problem.Of(http.StatusBadRequest).WriteTo(c.Writer)
		return domain.ScanCommand{}, false
	}
	return convert(cmd), true
}

// GenerateSBOM unmarshalls the payload and calls scanService.GenerateSBOM
func (h *HTTPController) GenerateSBOM(c *gin.Context) {
	ctx := c.Request.Context()

	newScan, ok := bindScanCommand(c, ctx, websocketScanCommandToScanCommand)
	if !ok {
		return
	}

	details := problem.Detailf("ImageHash=%s", newScan.ImageHash)

	ctx, err := h.scanService.ValidateGenerateSBOM(ctx, newScan)
	if err != nil {
		logger.L().Ctx(ctx).Error("validation error", helpers.Error(err),
			helpers.String("imageSlug", newScan.ImageSlug),
			helpers.String("imageTagNormalized", newScan.ImageTagNormalized),
			helpers.String("imageHash", newScan.ImageHash))
		h.recordRejection(ctx, "generateSBOM", err)
		_, _ = problem.Of(validationStatusCode(err)).Append(details).WriteTo(c.Writer)
		return
	}

	if !h.admitJob(c, ctx, "generateSBOM", newScan.JobID, details) {
		return
	}

	bgCtx := context.WithoutCancel(domain.WithScanPhaseUpdater(ctx, func(phase string) {
		h.ensureStatuses().markPhase(newScan.JobID, phase)
	}))
	h.runTrackedScan(bgCtx, newScan.JobID, "generateSBOM", h.scanService.GenerateSBOM,
		"service error - GenerateSBOM",
		helpers.String("imageSlug", newScan.ImageSlug),
		helpers.String("imageTagNormalized", newScan.ImageTagNormalized),
		helpers.String("imageHash", newScan.ImageHash))
}

// runTrackedScan submits scan to the worker pool and reports its result to both the scan
// metrics and the status store. GenerateSBOM, ScanCVE and ScanRegistry all report the same
// way, differing only in the endpoint label, the service call and the fields on the error
// log line, which is what errMsg and errDetails carry.
//
// ScanCP keeps its own copy: ErrPartialContainerProfile is a third outcome there, recorded
// as "partial" for the metric while still marking the job succeeded, and it has no
// equivalent in the other three.
//
// Called only once the caller has already reserved a slot via admitQueueSlot, so exactly
// one of the submitted closure's release() call or the shutdown fallback below owns
// returning that slot. The submitted closure's is deferred first so it still fires on the
// claimTrackedJob early return; the fallback only runs when submit() never handed the
// closure to the pool in the first place, so its own defer never gets the chance to.
func (h *HTTPController) runTrackedScan(bgCtx context.Context, jobID, endpoint string, scan func(context.Context) error, errMsg string, errDetails ...helpers.IDetails) {
	task := func() {
		defer h.release()
		if !h.claimTrackedJob(jobID) {
			return
		}
		start := time.Now()
		err := scan(bgCtx)
		outcome := "success"
		if err != nil {
			outcome = "error"
		}
		h.recordScan(bgCtx, endpoint, start, outcome, err)
		if err != nil {
			h.ensureStatuses().markFailed(jobID, scanFailureReason(outcome, err))
			logger.L().Ctx(bgCtx).Error(errMsg, append([]helpers.IDetails{helpers.Error(err)}, errDetails...)...)
			return
		}
		h.ensureStatuses().markSucceeded(jobID)
	}
	if !h.submit(task) {
		h.release()
		h.ensureStatuses().markAbandoned(jobID, domain.ScanReasonShutdownAbandoned)
	}
}

// Alive returns 200 OK
func (h *HTTPController) Alive(c *gin.Context) {
	_, _ = problem.Of(http.StatusOK).WriteTo(c.Writer)
}

// Ready calls scanService.Ready
func (h *HTTPController) Ready(c *gin.Context) {
	if !h.scanService.Ready(c.Request.Context()) {
		_, _ = problem.Of(http.StatusServiceUnavailable).WriteTo(c.Writer)
		return
	}

	_, _ = problem.Of(http.StatusOK).WriteTo(c.Writer)
}

// Diagnostics reports the scan mode and backend versions resolved at startup, so
// operators can query the running configuration directly instead of inferring it
// from logs. See domain.Diagnostics for the excluded (credential) fields.
func (h *HTTPController) Diagnostics(c *gin.Context) {
	if h.diagnostics == nil {
		c.JSON(http.StatusOK, domain.Diagnostics{})
		return
	}
	c.JSON(http.StatusOK, h.diagnostics(c.Request.Context()))
}

// ScanStatus reports the current lifecycle state for a previously accepted scan job.
func (h *HTTPController) ScanStatus(c *gin.Context) {
	status, ok := h.ensureStatuses().get(c.Param("jobID"))
	if !ok {
		_, _ = problem.Of(http.StatusNotFound).Append(problem.Detailf("jobID=%s", c.Param("jobID"))).WriteTo(c.Writer)
		return
	}
	c.JSON(http.StatusOK, status)
}

// ScanCP unmarshalls the payload and calls scanService.ScanCP
func (h *HTTPController) ScanCP(c *gin.Context) {
	ctx := c.Request.Context()

	newScan, ok := bindScanCommand(c, ctx, websocketScanCommandToScanCommand)
	if !ok {
		return
	}
	name, _ := newScan.Args[domain.ArgsName].(string)
	namespace, _ := newScan.Args[domain.ArgsNamespace].(string)

	details := problem.Detailf("Wlid=%s, Name=%s, Namespace=%s", newScan.Wlid, name, namespace)

	ctx, err := h.scanService.ValidateScanCP(ctx, newScan)
	if err != nil {
		logger.L().Ctx(ctx).Error("validation error", helpers.Error(err),
			helpers.String("wlid", newScan.Wlid),
			helpers.String("name", name),
			helpers.String("namespace", namespace))
		h.recordRejection(ctx, "scanCP", err)
		_, _ = problem.Of(validationStatusCode(err)).Append(details).WriteTo(c.Writer)
		return
	}

	if !h.admitJob(c, ctx, "scanCP", newScan.JobID, details) {
		return
	}

	bgCtx := context.WithoutCancel(domain.WithScanPhaseUpdater(ctx, func(phase string) {
		h.ensureStatuses().markPhase(newScan.JobID, phase)
	}))
	task := func() {
		defer h.release()
		if !h.claimTrackedJob(newScan.JobID) {
			return
		}
		start := time.Now()
		err = h.scanService.ScanCP(bgCtx)
		if err != nil {
			if errors.Is(err, domain.ErrPartialContainerProfile) {
				h.recordScan(bgCtx, "scanCP", start, "partial", err)
				h.ensureStatuses().markSucceeded(newScan.JobID)
				logger.L().Ctx(bgCtx).Warning("service warning - ScanCP", helpers.Error(err),
					helpers.String("wlid", newScan.Wlid),
					helpers.String("name", name),
					helpers.String("namespace", namespace))
			} else {
				h.recordScan(bgCtx, "scanCP", start, "error", err)
				h.ensureStatuses().markFailed(newScan.JobID, scanFailureReason("error", err))
				logger.L().Ctx(bgCtx).Error("service error - ScanCP", helpers.Error(err),
					helpers.String("wlid", newScan.Wlid),
					helpers.String("name", name),
					helpers.String("namespace", namespace))
			}
		} else {
			h.recordScan(bgCtx, "scanCP", start, "success", nil)
			h.ensureStatuses().markSucceeded(newScan.JobID)
		}
	}
	if !h.submit(task) {
		h.release()
		h.ensureStatuses().markAbandoned(newScan.JobID, domain.ScanReasonShutdownAbandoned)
	}
}

// ScanCVE unmarshalls the payload and calls scanService.ScanCVE
func (h *HTTPController) ScanCVE(c *gin.Context) {
	ctx := c.Request.Context()

	newScan, ok := bindScanCommand(c, ctx, websocketScanCommandToScanCommand)
	if !ok {
		return
	}

	details := problem.Detailf("Wlid=%s, ImageHash=%s", newScan.Wlid, newScan.ImageHash)

	ctx, err := h.scanService.ValidateScanCVE(ctx, newScan)
	if err != nil {
		logger.L().Ctx(ctx).Error("validation error", helpers.Error(err),
			helpers.String("imageSlug", newScan.ImageSlug),
			helpers.String("imageTagNormalized", newScan.ImageTagNormalized),
			helpers.String("imageHash", newScan.ImageHash))
		h.recordRejection(ctx, "scanCVE", err)
		_, _ = problem.Of(validationStatusCode(err)).Append(details).WriteTo(c.Writer)
		return
	}

	if !h.admitJob(c, ctx, "scanCVE", newScan.JobID, details) {
		return
	}

	bgCtx := context.WithoutCancel(domain.WithScanPhaseUpdater(ctx, func(phase string) {
		h.ensureStatuses().markPhase(newScan.JobID, phase)
	}))
	h.runTrackedScan(bgCtx, newScan.JobID, "scanCVE", h.scanService.ScanCVE,
		"service error - ScanCVE",
		helpers.String("wlid", newScan.Wlid),
		helpers.String("imageSlug", newScan.ImageSlug),
		helpers.String("imageTagNormalized", newScan.ImageTagNormalized),
		helpers.String("imageHash", newScan.ImageHash))
}

// validationStatusCode maps a validation/admission error to the HTTP status code that best
// describes it. ErrTooManyRequests reflects transient registry back-pressure caused by the
// caller's own request, so it maps to 429; ErrQueueFull reflects the controller's own local
// capacity, not anything wrong with the request, so it maps to 503 rather than either 429 or
// 400 -- a retry against the same instance may well succeed once the backlog drains.
// ErrDuplicateJobID reflects a conflict with another resource already tracked under the same
// jobID, so it maps to 409 -- retrying with the same jobID won't help until that job finishes,
// but retrying with a fresh jobID will.
func validationStatusCode(err error) int {
	switch {
	case errors.Is(err, domain.ErrTooManyRequests):
		return http.StatusTooManyRequests
	case errors.Is(err, domain.ErrQueueFull):
		return http.StatusServiceUnavailable
	case errors.Is(err, domain.ErrDuplicateJobID):
		return http.StatusConflict
	}
	return http.StatusBadRequest
}

func websocketScanCommandToScanCommand(c wssc.WebsocketScanCommand) domain.ScanCommand {
	imageTagNormalized := tools.NormalizeReference(c.ImageTag)
	command := domain.ScanCommand{
		CredentialsList:    c.Credentialslist,
		ImageHash:          v1.NormalizeImageID(c.ImageHash, c.ImageTag),
		Wlid:               c.Wlid,
		ImageTag:           c.ImageTag,
		ImageTagNormalized: imageTagNormalized,
		JobID:              c.JobID,
		ContainerName:      c.ContainerName,
		LastAction:         c.LastAction,
		ParentJobID:        c.ParentJobID,
		Args:               c.Args,
		Session:            sessionChainToSession(c.Session),
	}
	if slug, err := names.ImageInfoToSlug(imageTagNormalized, c.ImageHash); err == nil {
		command.ImageSlug = slug
	}
	if c.InstanceID != nil {
		command.InstanceID = *c.InstanceID
	}
	return command
}

func sessionChainToSession(s wssc.SessionChain) domain.Session {
	return domain.Session{
		JobIDs: s.JobIDs,
	}
}

func (h *HTTPController) ScanRegistry(c *gin.Context) {
	ctx := c.Request.Context()

	newScan, ok := bindScanCommand(c, ctx, registryScanCommandToScanCommand)
	if !ok {
		return
	}

	details := problem.Detailf("ImageTag=%s", newScan.ImageTag)

	ctx, err := h.scanService.ValidateScanRegistry(ctx, newScan)
	if err != nil {
		logger.L().Ctx(ctx).Error("validation error", helpers.Error(err),
			helpers.String("imageSlug", newScan.ImageSlug),
			helpers.String("imageTagNormalized", newScan.ImageTagNormalized),
			helpers.String("imageHash", newScan.ImageHash))
		h.recordRejection(ctx, "scanRegistry", err)
		_, _ = problem.Of(validationStatusCode(err)).Append(details).WriteTo(c.Writer)
		return
	}

	if !h.admitJob(c, ctx, "scanRegistry", newScan.JobID, details) {
		return
	}

	bgCtx := context.WithoutCancel(domain.WithScanPhaseUpdater(ctx, func(phase string) {
		h.ensureStatuses().markPhase(newScan.JobID, phase)
	}))
	h.runTrackedScan(bgCtx, newScan.JobID, "scanRegistry", h.scanService.ScanRegistry,
		"service error - ScanRegistry",
		helpers.String("imageSlug", newScan.ImageSlug),
		helpers.String("imageTagNormalized", newScan.ImageTagNormalized),
		helpers.String("imageHash", newScan.ImageHash))
}

// registryScanCommandToScanCommand converts a RegistryScanCommand into a domain.ScanCommand, populating normalized image reference, image hash, and image slug.
func registryScanCommandToScanCommand(c wssc.RegistryScanCommand) domain.ScanCommand {
	imageTagNormalized := tools.NormalizeReference(c.ImageTag)
	command := domain.ScanCommand{
		CredentialsList:    c.Credentialslist,
		ImageHash:          v1.NormalizeImageID("", c.ImageTag),
		ImageTag:           c.ImageTag,
		ImageTagNormalized: imageTagNormalized,
		JobID:              c.JobID,
		ParentJobID:        c.ParentJobID,
		Args:               c.Args,
		Session:            sessionChainToSession(c.Session),
	}
	if slug, err := names.ImageInfoToSlug(imageTagNormalized, "nohash"); err == nil {
		command.ImageSlug = slug
	}
	return command
}

// Shutdown abandons queued-but-not-started scans immediately and waits only for
// currently running scans to finish, bounded by timeout. workerPool.Stop() (as opposed
// to StopWait()) already caps the wait at "currently running tasks", matching this
// package's acceptance criteria of abandoning pending work rather than racing through
// the whole backlog; timeout is the backstop for a running task that ignores ctx
// cancellation (see #450) and would otherwise block Stop() indefinitely. timeout should
// be kept safely under the pod's terminationGracePeriodSeconds so this path has a
// chance to log before the kubelet SIGKILLs the process.
func (h *HTTPController) Shutdown(timeout time.Duration) {
	logger.L().Info("purging SBOM creation queue",
		helpers.String("remaining jobs", strconv.Itoa(h.workerPool.WaitingQueueSize())),
		helpers.String("timeout", timeout.String()))

	// Taking submitGate for write blocks until every submit() call currently holding it
	// for read has returned, so no caller can still be mid-Submit once this unlocks. Every
	// submit() call from here on sees shuttingDown and never reaches workerPool.Submit, so
	// the close(taskQueue) inside workerPool.Stop() below can never race one. See #758.
	h.submitGate.Lock()
	h.shuttingDown = true
	h.submitGate.Unlock()

	h.ensureStatuses().markAbandonedQueued(domain.ScanReasonShutdownAbandoned)

	drained := make(chan struct{})
	go func() {
		h.workerPool.Stop() // abandon the queue, wait only for in-flight scans
		close(drained)
	}()

	select {
	case <-drained:
		logger.L().Info("SBOM creation queue drained")
	case <-time.After(timeout):
		logger.L().Warning("shutdown timeout reached, abandoning in-flight scans",
			helpers.String("timeout", timeout.String()))
	}
}
