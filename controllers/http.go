package controllers

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"time"

	wssc "github.com/armosec/armoapi-go/apis"
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
	scanService ports.ScanService
	workerPool  *workerpool.WorkerPool
	metrics     *metrics.Metrics
}

// NewHTTPController initializes the HTTPController struct with the injected scanService
func NewHTTPController(scanService ports.ScanService, concurrency int) *HTTPController {
	return &HTTPController{
		scanService: scanService,
		workerPool:  workerpool.New(concurrency),
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

// recordScan records the outcome and duration of a background scan job for the given endpoint.
func (h HTTPController) recordScan(endpoint string, start time.Time, success bool) {
	if h.metrics == nil {
		return
	}
	attrs := metric.WithAttributes(
		attribute.String("endpoint", endpoint),
		attribute.Bool("success", success),
	)
	h.metrics.ScanCounter.Add(context.Background(), 1, attrs)
	h.metrics.ScanDuration.Record(context.Background(), time.Since(start).Seconds(), attrs)
}

// recordRejection records a validation-time rejection for the given endpoint.
func (h HTTPController) recordRejection(endpoint string) {
	if h.metrics == nil {
		return
	}
	h.metrics.RejectCounter.Add(context.Background(), 1, metric.WithAttributes(attribute.String("endpoint", endpoint)))
}

// GenerateSBOM unmarshalls the payload and calls scanService.GenerateSBOM
func (h HTTPController) GenerateSBOM(c *gin.Context) {
	ctx := c.Request.Context()

	var websocketScanCommand wssc.WebsocketScanCommand
	err := c.ShouldBindJSON(&websocketScanCommand)
	if err != nil {
		logger.L().Ctx(ctx).Error("handler error", helpers.Error(err))
		_, _ = problem.Of(http.StatusBadRequest).WriteTo(c.Writer)
		return
	}

	newScan := websocketScanCommandToScanCommand(websocketScanCommand)

	details := problem.Detailf("ImageHash=%s", newScan.ImageHash)

	ctx, err = h.scanService.ValidateGenerateSBOM(ctx, newScan)
	if err != nil {
		logger.L().Ctx(ctx).Error("validation error", helpers.Error(err),
			helpers.String("imageSlug", newScan.ImageSlug),
			helpers.String("imageTagNormalized", newScan.ImageTagNormalized),
			helpers.String("imageHash", newScan.ImageHash))
		h.recordRejection("generateSBOM")
		_, _ = problem.Of(validationStatusCode(err)).Append(details).WriteTo(c.Writer)
		return
	}

	_, _ = problem.Of(http.StatusOK).Append(details).WriteTo(c.Writer)

	bgCtx := context.WithoutCancel(ctx)
	start := time.Now()
	h.workerPool.Submit(func() {
		err = h.scanService.GenerateSBOM(bgCtx)
		h.recordScan("generateSBOM", start, err == nil)
		if err != nil {
			logger.L().Ctx(bgCtx).Error("service error - GenerateSBOM", helpers.Error(err),
				helpers.String("imageSlug", newScan.ImageSlug),
				helpers.String("imageTagNormalized", newScan.ImageTagNormalized),
				helpers.String("imageHash", newScan.ImageHash))
		}
	})
}

// Alive returns 200 OK
func (h HTTPController) Alive(c *gin.Context) {
	_, _ = problem.Of(http.StatusOK).WriteTo(c.Writer)
}

// Ready calls scanService.Ready
func (h HTTPController) Ready(c *gin.Context) {
	if !h.scanService.Ready(c.Request.Context()) {
		_, _ = problem.Of(http.StatusServiceUnavailable).WriteTo(c.Writer)
		return
	}

	_, _ = problem.Of(http.StatusOK).WriteTo(c.Writer)
}

// ScanCP unmarshalls the payload and calls scanService.ScanCP
func (h HTTPController) ScanCP(c *gin.Context) {
	ctx := c.Request.Context()

	var websocketScanCommand wssc.WebsocketScanCommand
	err := c.ShouldBindJSON(&websocketScanCommand)
	if err != nil {
		logger.L().Ctx(ctx).Error("handler error", helpers.Error(err))
		_, _ = problem.Of(http.StatusBadRequest).WriteTo(c.Writer)
		return
	}

	newScan := websocketScanCommandToScanCommand(websocketScanCommand)
	name, _ := newScan.Args[domain.ArgsName].(string)
	namespace, _ := newScan.Args[domain.ArgsNamespace].(string)

	details := problem.Detailf("Wlid=%s, Name=%s, Namespace=%s", newScan.Wlid, name, namespace)

	ctx, err = h.scanService.ValidateScanCP(ctx, newScan)
	if err != nil {
		logger.L().Ctx(ctx).Error("validation error", helpers.Error(err),
			helpers.String("wlid", newScan.Wlid),
			helpers.String("name", name),
			helpers.String("namespace", namespace))
		h.recordRejection("scanCP")
		_, _ = problem.Of(validationStatusCode(err)).Append(details).WriteTo(c.Writer)
		return
	}

	_, _ = problem.Of(http.StatusOK).Append(details).WriteTo(c.Writer)

	bgCtx := context.WithoutCancel(ctx)
	start := time.Now()
	h.workerPool.Submit(func() {
		err = h.scanService.ScanCP(bgCtx)
		h.recordScan("scanCP", start, err == nil)
		if err != nil {
			if errors.Is(err, domain.ErrPartialContainerProfile) {
				logger.L().Ctx(bgCtx).Warning("service warning - ScanCP", helpers.Error(err),
					helpers.String("wlid", newScan.Wlid),
					helpers.String("name", name),
					helpers.String("namespace", namespace))
			} else {
				logger.L().Ctx(bgCtx).Error("service error - ScanCP", helpers.Error(err),
					helpers.String("wlid", newScan.Wlid),
					helpers.String("name", name),
					helpers.String("namespace", namespace))
			}
		}
	})
}

// ScanCVE unmarshalls the payload and calls scanService.ScanCVE
func (h HTTPController) ScanCVE(c *gin.Context) {
	ctx := c.Request.Context()

	var websocketScanCommand wssc.WebsocketScanCommand
	err := c.ShouldBindJSON(&websocketScanCommand)
	if err != nil {
		logger.L().Ctx(ctx).Error("handler error", helpers.Error(err))
		_, _ = problem.Of(http.StatusBadRequest).WriteTo(c.Writer)
		return
	}

	newScan := websocketScanCommandToScanCommand(websocketScanCommand)

	details := problem.Detailf("Wlid=%s, ImageHash=%s", newScan.Wlid, newScan.ImageHash)

	ctx, err = h.scanService.ValidateScanCVE(ctx, newScan)
	if err != nil {
		logger.L().Ctx(ctx).Error("validation error", helpers.Error(err),
			helpers.String("imageSlug", newScan.ImageSlug),
			helpers.String("imageTagNormalized", newScan.ImageTagNormalized),
			helpers.String("imageHash", newScan.ImageHash))
		h.recordRejection("scanCVE")
		_, _ = problem.Of(validationStatusCode(err)).Append(details).WriteTo(c.Writer)
		return
	}

	_, _ = problem.Of(http.StatusOK).Append(details).WriteTo(c.Writer)

	bgCtx := context.WithoutCancel(ctx)
	start := time.Now()
	h.workerPool.Submit(func() {
		err = h.scanService.ScanCVE(bgCtx)
		h.recordScan("scanCVE", start, err == nil)
		if err != nil {
			logger.L().Ctx(bgCtx).Error("service error - ScanCVE", helpers.Error(err),
				helpers.String("wlid", newScan.Wlid),
				helpers.String("imageSlug", newScan.ImageSlug),
				helpers.String("imageTagNormalized", newScan.ImageTagNormalized),
				helpers.String("imageHash", newScan.ImageHash))
		}
	})
}

// validationStatusCode maps a validation error to the HTTP status code that best
// describes it. ErrTooManyRequests reflects transient registry back-pressure, not
// a malformed request, so it maps to 429 rather than 400.
func validationStatusCode(err error) int {
	if errors.Is(err, domain.ErrTooManyRequests) {
		return http.StatusTooManyRequests
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

func (h HTTPController) ScanRegistry(c *gin.Context) {
	ctx := c.Request.Context()

	var registryScanCommand wssc.RegistryScanCommand
	err := c.ShouldBindJSON(&registryScanCommand)
	if err != nil {
		logger.L().Ctx(ctx).Error("handler error", helpers.Error(err))
		_, _ = problem.Of(http.StatusBadRequest).WriteTo(c.Writer)
		return
	}

	newScan := registryScanCommandToScanCommand(registryScanCommand)

	details := problem.Detailf("ImageTag=%s", newScan.ImageTag)

	ctx, err = h.scanService.ValidateScanRegistry(ctx, newScan)
	if err != nil {
		logger.L().Ctx(ctx).Error("validation error", helpers.Error(err),
			helpers.String("imageSlug", newScan.ImageSlug),
			helpers.String("imageTagNormalized", newScan.ImageTagNormalized),
			helpers.String("imageHash", newScan.ImageHash))
		h.recordRejection("scanRegistry")
		_, _ = problem.Of(validationStatusCode(err)).Append(details).WriteTo(c.Writer)
		return
	}

	_, _ = problem.Of(http.StatusOK).Append(details).WriteTo(c.Writer)

	bgCtx := context.WithoutCancel(ctx)
	start := time.Now()
	h.workerPool.Submit(func() {
		err = h.scanService.ScanRegistry(bgCtx)
		h.recordScan("scanRegistry", start, err == nil)
		if err != nil {
			logger.L().Ctx(bgCtx).Error("service error - ScanRegistry", helpers.Error(err),
				helpers.String("imageSlug", newScan.ImageSlug),
				helpers.String("imageTagNormalized", newScan.ImageTagNormalized),
				helpers.String("imageHash", newScan.ImageHash))
		}
	})
}

func registryScanCommandToScanCommand(c wssc.RegistryScanCommand) domain.ScanCommand {
	command := domain.ScanCommand{
		CredentialsList:    c.Credentialslist,
		ImageTag:           c.ImageTag,
		ImageTagNormalized: tools.NormalizeReference(c.ImageTag),
		JobID:              c.JobID,
		ParentJobID:        c.ParentJobID,
		Args:               c.Args,
		Session:            sessionChainToSession(c.Session),
	}
	if slug, err := names.ImageInfoToSlug(c.ImageTag, "nohash"); err == nil {
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
func (h HTTPController) Shutdown(timeout time.Duration) {
	logger.L().Info("purging SBOM creation queue",
		helpers.String("remaining jobs", strconv.Itoa(h.workerPool.WaitingQueueSize())),
		helpers.String("timeout", timeout.String()))

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
