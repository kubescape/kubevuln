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

type HTTPController struct {
	scanService ports.ScanService
}

func NewHTTPController(scanService ports.ScanService) *HTTPController {
	return &HTTPController{
		scanService: scanService,
	}
}

func (h HTTPController) GenerateSBOM(c *gin.Context) {
	c.Header("Content-Type", "application/json")

	var newScan wssc.WebsocketScanCommand
	err := c.ShouldBindJSON(&newScan)
	if err != nil {
		logger.L().Ctx(c.Request.Context()).Error("handler error", helpers.Error(err))
		c.JSON(http.StatusBadRequest, nil)
		return
	}

	err = h.scanService.GenerateSBOM(c.Request.Context(), newScan.ImageHash, domain.Workload(newScan))
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

func (h HTTPController) ScanCVE(c *gin.Context) {
	c.Header("Content-Type", "application/json")

	var newScan wssc.WebsocketScanCommand
	err := c.ShouldBindJSON(&newScan)
	if err != nil {
		logger.L().Ctx(c.Request.Context()).Error("handler error", helpers.Error(err))
		c.JSON(http.StatusBadRequest, nil)
		return
	}

	err = h.scanService.ScanCVE(c.Request.Context(), newScan.Wlid, newScan.ImageHash, domain.Workload(newScan))
	if err != nil {
		logger.L().Ctx(c.Request.Context()).Error("service error", helpers.Error(err))
		c.JSON(http.StatusInternalServerError, nil)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status": "success",
		"data":   "new CVEs created",
	})
}
