package controllers

import (
	"net/http"
	"strconv"

	wssc "github.com/armosec/armoapi-go/apis"
	"github.com/gammazero/workerpool"
	"github.com/gin-gonic/gin"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/names"
	v1 "github.com/kubescape/kubevuln/adapters/v1"
	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/kubevuln/core/ports"
	"github.com/kubescape/kubevuln/internal/tools"
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
		_, _ = problem.Of(http.StatusInternalServerError).Append(details).WriteTo(c.Writer)
		return
	}

	_, _ = problem.Of(http.StatusOK).Append(details).WriteTo(c.Writer)

	h.workerPool.Submit(func() {
		err = h.scanService.GenerateSBOM(ctx)
		if err != nil {
			logger.L().Ctx(ctx).Error("service error - GenerateSBOM", helpers.Error(err),
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

// ScanAP unmarshalls the payload and calls scanService.ScanAP
func (h HTTPController) ScanAP(c *gin.Context) {
	ctx := c.Request.Context()

	var websocketScanCommand wssc.WebsocketScanCommand
	err := c.ShouldBindJSON(&websocketScanCommand)
	if err != nil {
		logger.L().Ctx(ctx).Error("handler error", helpers.Error(err))
		_, _ = problem.Of(http.StatusBadRequest).WriteTo(c.Writer)
		return
	}

	newScan := websocketScanCommandToScanCommand(websocketScanCommand)
	name := newScan.Args[domain.ArgsName].(string)
	namespace := newScan.Args[domain.ArgsNamespace].(string)

	details := problem.Detailf("Wlid=%s, Name=%s, Namespace=%s", newScan.Wlid, name, namespace)

	ctx, err = h.scanService.ValidateScanAP(ctx, newScan)
	if err != nil {
		logger.L().Ctx(ctx).Error("validation error", helpers.Error(err),
			helpers.String("wlid", newScan.Wlid),
			helpers.String("name", name),
			helpers.String("namespace", namespace))
		_, _ = problem.Of(http.StatusInternalServerError).Append(details).WriteTo(c.Writer)
		return
	}

	_, _ = problem.Of(http.StatusOK).Append(details).WriteTo(c.Writer)

	h.workerPool.Submit(func() {
		err = h.scanService.ScanAP(ctx)
		if err != nil {
			logger.L().Ctx(ctx).Error("service error - ScanAP", helpers.Error(err),
				helpers.String("wlid", newScan.Wlid),
				helpers.String("name", name),
				helpers.String("namespace", namespace))
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
		_, _ = problem.Of(http.StatusInternalServerError).Append(details).WriteTo(c.Writer)
		return
	}

	_, _ = problem.Of(http.StatusOK).Append(details).WriteTo(c.Writer)

	h.workerPool.Submit(func() {
		err = h.scanService.ScanCVE(ctx)
		if err != nil {
			logger.L().Ctx(ctx).Error("service error - ScanCVE", helpers.Error(err),
				helpers.String("wlid", newScan.Wlid),
				helpers.String("imageSlug", newScan.ImageSlug),
				helpers.String("imageTagNormalized", newScan.ImageTagNormalized),
				helpers.String("imageHash", newScan.ImageHash))
		}
	})
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
		_, _ = problem.Of(http.StatusInternalServerError).Append(details).WriteTo(c.Writer)
		return
	}

	_, _ = problem.Of(http.StatusOK).Append(details).WriteTo(c.Writer)

	h.workerPool.Submit(func() {
		err = h.scanService.ScanRegistry(ctx)
		if err != nil {
			logger.L().Ctx(ctx).Error("service error - ScanRegistry", helpers.Error(err),
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

func (h HTTPController) Shutdown() {
	logger.L().Info("purging SBOM creation queue",
		helpers.String("remaining jobs", strconv.Itoa(h.workerPool.WaitingQueueSize())))
	h.workerPool.StopWait()
}
