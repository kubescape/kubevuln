package controllers

import (
	"net/http"

	wssc "github.com/armosec/armoapi-go/apis"
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
}

// NewHTTPController initializes the HTTPController struct with the injected scanService
func NewHTTPController(scanService ports.ScanService) *HTTPController {
	return &HTTPController{
		scanService: scanService,
	}
}

// GenerateSBOM unmarshalls the payload and calls scanService.GenerateSBOM
func (h HTTPController) GenerateSBOM(c *gin.Context) {
	var newScan wssc.WebsocketScanCommand
	err := c.ShouldBindJSON(&newScan)
	if err != nil {
		logger.L().Ctx(c.Request.Context()).Error("handler error", helpers.Error(err))
		problem.Of(http.StatusBadRequest).WriteTo(c.Writer)
		return
	}

	// TODO add proper transformation of wssc.WebsocketScanCommand to domain.ScanCommand
	details := problem.Detailf("ImageHash=%s", newScan.ImageHash)

	err = h.scanService.GenerateSBOM(c.Request.Context(), newScan.ImageHash, domain.ScanCommand(newScan))
	if err != nil {
		logger.L().Ctx(c.Request.Context()).Error("service error", helpers.Error(err))
		problem.Of(http.StatusInternalServerError).Append(details).WriteTo(c.Writer)
		return
	}

	problem.Of(http.StatusOK).Append(details).WriteTo(c.Writer)
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
	var newScan wssc.WebsocketScanCommand
	err := c.ShouldBindJSON(&newScan)
	if err != nil {
		logger.L().Ctx(c.Request.Context()).Error("handler error", helpers.Error(err))
		problem.Of(http.StatusBadRequest).WriteTo(c.Writer)
		return
	}

	// TODO add proper transformation of wssc.WebsocketScanCommand to domain.ScanCommand
	details := problem.Detailf("Wlid=%s, ImageHash=%s", newScan.Wlid, newScan.ImageHash)

	err = h.scanService.ScanCVE(c.Request.Context(), newScan.Wlid, newScan.ImageHash, domain.ScanCommand(newScan))
	if err != nil {
		logger.L().Ctx(c.Request.Context()).Error("service error", helpers.Error(err))
		problem.Of(http.StatusInternalServerError).Append(details).WriteTo(c.Writer)
		return
	}

	problem.Of(http.StatusOK).Append(details).WriteTo(c.Writer)
}
