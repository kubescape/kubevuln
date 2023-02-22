package controllers

import (
	"net/http"
	"strconv"

	wssc "github.com/armosec/armoapi-go/apis"
	"github.com/gammazero/workerpool"
	"github.com/gin-gonic/gin"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/kubevuln/core/ports"
	"schneider.vip/problem"
)

// HTTPController maps ScanService ports to gin handlers that can be mapped to paths and methods
// this mapping is usually done in main()
type HTTPController struct {
	scanService ports.ScanService
	workerPool  *workerpool.WorkerPool
}

// NewHTTPController initializes the HTTPController struct with the injected scanService
func NewHTTPController(scanService ports.ScanService, concurrency int) *HTTPController {
	return &HTTPController{
		scanService: scanService,
		workerPool:  workerpool.New(concurrency),
	}
}

// GenerateSBOM unmarshalls the payload and calls scanService.GenerateSBOM
func (h HTTPController) GenerateSBOM(c *gin.Context) {
	ctx := c.Request.Context()

	var newScan wssc.WebsocketScanCommand
	err := c.ShouldBindJSON(&newScan)
	if err != nil {
		logger.L().Ctx(ctx).Error("handler error", helpers.Error(err))
		problem.Of(http.StatusBadRequest).WriteTo(c.Writer)
		return
	}

	// TODO add proper transformation of wssc.WebsocketScanCommand to domain.ScanCommand
	details := problem.Detailf("ImageHash=%s", newScan.ImageHash)

	ctx, err = h.scanService.ValidateGenerateSBOM(ctx, domain.ScanCommand(newScan))
	if err != nil {
		logger.L().Ctx(ctx).Error("validation error", helpers.Error(err))
		problem.Of(http.StatusInternalServerError).Append(details).WriteTo(c.Writer)
		return
	}

	problem.Of(http.StatusOK).Append(details).WriteTo(c.Writer)

	h.workerPool.Submit(func() {
		err = h.scanService.GenerateSBOM(ctx)
		if err != nil {
			logger.L().Ctx(ctx).Error("service error", helpers.Error(err))
		}
	})
}

// Ready calls scanService.Ready
func (h HTTPController) Ready(c *gin.Context) {
	if !h.scanService.Ready() {
		problem.Of(http.StatusServiceUnavailable).WriteTo(c.Writer)
		return
	}

	problem.Of(http.StatusOK).WriteTo(c.Writer)
}

// ScanCVE unmarshalls the payload and calls scanService.ScanCVE
func (h HTTPController) ScanCVE(c *gin.Context) {
	ctx := c.Request.Context()

	var newScan wssc.WebsocketScanCommand
	err := c.ShouldBindJSON(&newScan)
	if err != nil {
		logger.L().Ctx(ctx).Error("handler error", helpers.Error(err))
		problem.Of(http.StatusBadRequest).WriteTo(c.Writer)
		return
	}

	// TODO add proper transformation of wssc.WebsocketScanCommand to domain.ScanCommand
	details := problem.Detailf("Wlid=%s, ImageHash=%s", newScan.Wlid, newScan.ImageHash)

	ctx, err = h.scanService.ValidateScanCVE(ctx, domain.ScanCommand(newScan))
	if err != nil {
		logger.L().Ctx(ctx).Error("validation error", helpers.Error(err))
		problem.Of(http.StatusInternalServerError).Append(details).WriteTo(c.Writer)
		return
	}

	problem.Of(http.StatusOK).Append(details).WriteTo(c.Writer)

	h.workerPool.Submit(func() {
		err = h.scanService.ScanCVE(ctx)
		if err != nil {
			logger.L().Ctx(ctx).Error("service error", helpers.Error(err))
		}
	})
}

func (h HTTPController) Shutdown() {
	logger.L().Info("purging SBOM creation queue", helpers.String("remaining jobs", strconv.Itoa(h.workerPool.WaitingQueueSize())))
	h.workerPool.StopWait()
}
