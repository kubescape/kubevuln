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

	var websocketScanCommand wssc.WebsocketScanCommand
	err := c.ShouldBindJSON(&websocketScanCommand)
	if err != nil {
		logger.L().Ctx(ctx).Error("handler error", helpers.Error(err))
		problem.Of(http.StatusBadRequest).WriteTo(c.Writer)
		return
	}

	newScan := websocketScanCommandToScanCommand(websocketScanCommand)

	details := problem.Detailf("ImageHash=%s", newScan.ImageHash)

	ctx, err = h.scanService.ValidateGenerateSBOM(ctx, newScan)
	if err != nil {
		logger.L().Ctx(ctx).Error("validation error", helpers.Error(err), helpers.String("imageID", newScan.ImageHash))
		problem.Of(http.StatusInternalServerError).Append(details).WriteTo(c.Writer)
		return
	}

	problem.Of(http.StatusOK).Append(details).WriteTo(c.Writer)

	h.workerPool.Submit(func() {
		err = h.scanService.GenerateSBOM(ctx)
		if err != nil {
			logger.L().Ctx(ctx).Error("service error", helpers.Error(err), helpers.String("imageID", newScan.ImageHash))
		}
	})
}

// Alive returns 200 OK
func (h HTTPController) Alive(c *gin.Context) {
	problem.Of(http.StatusOK).WriteTo(c.Writer)
}

// Ready calls scanService.Ready
func (h HTTPController) Ready(c *gin.Context) {
	if !h.scanService.Ready(c.Request.Context()) {
		problem.Of(http.StatusServiceUnavailable).WriteTo(c.Writer)
		return
	}

	problem.Of(http.StatusOK).WriteTo(c.Writer)
}

// ScanCVE unmarshalls the payload and calls scanService.ScanCVE
func (h HTTPController) ScanCVE(c *gin.Context) {
	ctx := c.Request.Context()

	var websocketScanCommand wssc.WebsocketScanCommand
	err := c.ShouldBindJSON(&websocketScanCommand)
	if err != nil {
		logger.L().Ctx(ctx).Error("handler error", helpers.Error(err))
		problem.Of(http.StatusBadRequest).WriteTo(c.Writer)
		return
	}

	newScan := websocketScanCommandToScanCommand(websocketScanCommand)

	details := problem.Detailf("Wlid=%s, ImageHash=%s", newScan.Wlid, newScan.ImageHash)

	ctx, err = h.scanService.ValidateScanCVE(ctx, newScan)
	if err != nil {
		logger.L().Ctx(ctx).Error("validation error", helpers.Error(err), helpers.String("wlid", newScan.Wlid), helpers.String("imageID", newScan.ImageHash))
		problem.Of(http.StatusInternalServerError).Append(details).WriteTo(c.Writer)
		return
	}

	problem.Of(http.StatusOK).Append(details).WriteTo(c.Writer)

	h.workerPool.Submit(func() {
		err = h.scanService.ScanCVE(ctx)
		if err != nil {
			logger.L().Ctx(ctx).Error("service error", helpers.Error(err), helpers.String("wlid", newScan.Wlid), helpers.String("imageID", newScan.ImageHash))
		}
	})
}

func websocketScanCommandToScanCommand(c wssc.WebsocketScanCommand) domain.ScanCommand {
	command := domain.ScanCommand{
		Credentialslist: c.Credentialslist,
		ImageHash:       c.ImageHash,
		Wlid:            c.Wlid,
		ImageTag:        c.ImageTag,
		JobID:           c.JobID,
		ContainerName:   c.ContainerName,
		LastAction:      c.LastAction,
		ParentJobID:     c.ParentJobID,
		Args:            c.Args,
		Session:         sessionChainToSession(c.Session),
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
		problem.Of(http.StatusBadRequest).WriteTo(c.Writer)
		return
	}

	newScan := registryScanCommandToScanCommand(registryScanCommand)

	details := problem.Detailf("ImageTag=%s", newScan.ImageTag)

	ctx, err = h.scanService.ValidateScanRegistry(ctx, newScan)
	if err != nil {
		logger.L().Ctx(ctx).Error("validation error", helpers.Error(err), helpers.String("imageID", newScan.ImageTag))
		problem.Of(http.StatusInternalServerError).Append(details).WriteTo(c.Writer)
		return
	}

	problem.Of(http.StatusOK).Append(details).WriteTo(c.Writer)

	h.workerPool.Submit(func() {
		err = h.scanService.ScanRegistry(ctx)
		if err != nil {
			logger.L().Ctx(ctx).Error("service error", helpers.Error(err), helpers.String("imageID", newScan.ImageTag))
		}
	})
}

func registryScanCommandToScanCommand(c wssc.RegistryScanCommand) domain.ScanCommand {
	command := domain.ScanCommand{
		Credentialslist: c.Credentialslist,
		ImageTag:        c.ImageTag,
		JobID:           c.JobID,
		ParentJobID:     c.ParentJobID,
		Args:            c.Args,
		Session:         sessionChainToSession(c.Session),
	}
	return command
}

func (h HTTPController) Shutdown() {
	logger.L().Info("purging SBOM creation queue", helpers.String("remaining jobs", strconv.Itoa(h.workerPool.WaitingQueueSize())))
	h.workerPool.StopWait()
}
