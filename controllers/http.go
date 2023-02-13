package controllers

import (
	"net/http"

	wssc "github.com/armosec/armoapi-go/apis"
	"github.com/gin-gonic/gin"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/kubevuln/core/ports"
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
	c.Header("Content-Type", "application/json")

	var newScan wssc.WebsocketScanCommand
	err := c.ShouldBindJSON(&newScan)
	if err != nil {
		logger.L().Ctx(c.Request.Context()).Error("handler error", helpers.Error(err))
		c.JSON(http.StatusBadRequest, nil)
		return
	}

	// TODO add proper transformation of wssc.WebsocketScanCommand to domain.ScanCommand

	err = h.scanService.GenerateSBOM(c.Request.Context(), newScan.ImageHash, domain.ScanCommand(newScan))
	if err != nil {
		logger.L().Ctx(c.Request.Context()).Error("service error", helpers.Error(err))
		c.JSON(http.StatusInternalServerError, nil)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status": "success",
		"data":   "new SBOMs created",
	})
}

// Ready calls scanService.Ready
func (h HTTPController) Ready(c *gin.Context) {
	c.Header("Content-Type", "application/json")

	if !h.scanService.Ready() {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"status": "Scanner not ready",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status": "UP",
	})
}

// ScanCVE unmarshalls the payload and calls scanService.ScanCVE
func (h HTTPController) ScanCVE(c *gin.Context) {
	c.Header("Content-Type", "application/json")

	var newScan wssc.WebsocketScanCommand
	err := c.ShouldBindJSON(&newScan)
	if err != nil {
		logger.L().Ctx(c.Request.Context()).Error("handler error", helpers.Error(err))
		c.JSON(http.StatusBadRequest, nil)
		return
	}

	// TODO add proper transformation of wssc.WebsocketScanCommand to domain.ScanCommand

	err = h.scanService.ScanCVE(c.Request.Context(), newScan.Wlid, newScan.ImageHash, domain.ScanCommand(newScan))
	if err != nil {
		logger.L().Ctx(c.Request.Context()).Error("service error", helpers.Error(err))
		c.JSON(http.StatusInternalServerError, nil)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status": "success",
		"data":   "new CVE manifest created",
	})
}
