package app

import (
	"net/http"

	wssc "github.com/armosec/armoapi-go/apis"
	"github.com/gin-gonic/gin"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
)

func (s *Server) HealthCheck() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Content-Type", "application/json")

		if !s.scannerService.Ready() {
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"status": "Scanner not ready",
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"status": "UP",
		})
	}
}

func (s *Server) CreateCVE() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Content-Type", "application/json")

		var newScan wssc.WebsocketScanCommand
		err := c.ShouldBindJSON(&newScan)
		if err != nil {
			logger.L().Ctx(c.Request.Context()).Error("handler error", helpers.Error(err))
			c.JSON(http.StatusBadRequest, nil)
			return
		}

		err = s.cveService.New(newScan)
		if err != nil {
			logger.L().Ctx(c.Request.Context()).Error("service error", helpers.Error(err))
			c.JSON(http.StatusInternalServerError, nil)
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"status": "success",
			"data":   "new CVE scan created",
		})
	}
}

func (s *Server) DbCommand() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Content-Type", "application/json")

		var command wssc.DBCommand
		err := c.ShouldBindJSON(&command)
		if err != nil {
			logger.L().Ctx(c.Request.Context()).Error("handler error", helpers.Error(err))
			c.JSON(http.StatusBadRequest, nil)
			return
		}

		err = s.scannerService.NewDbCommand(command)
		if err != nil {
			logger.L().Ctx(c.Request.Context()).Error("service error", helpers.Error(err))
			c.JSON(http.StatusInternalServerError, nil)
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"status": "success",
			"data":   "DB command executed",
		})
	}
}
