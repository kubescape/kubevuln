package app

import (
	"context"

	"github.com/gin-gonic/gin"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	api "github.com/kubescape/kubevuln/pkg/api/v1"
	"github.com/kubescape/kubevuln/pkg/repository"
)

type Server struct {
	router         *gin.Engine
	cveService     api.CVEService
	sbomService    api.SBOMService
	scannerService api.ScannerService
}

func NewServer(router *gin.Engine, cveService api.CVEService, sbomService api.SBOMService, scannerService api.ScannerService) *Server {
	return &Server{
		router:         router,
		cveService:     cveService,
		sbomService:    sbomService,
		scannerService: scannerService,
	}
}

func NewMockServer() *Server {
	storage := repository.NewStorage()
	return &Server{
		router:         gin.Default(),
		cveService:     api.NewCVEService(storage),
		sbomService:    api.NewSBOMService(storage),
		scannerService: api.NewScannerService(),
	}
}

func (s *Server) Run(ctx context.Context) error {
	// run function that initializes the routes
	r := s.Routes()

	// run the server through the router
	err := r.Run()

	if err != nil {
		logger.L().Ctx(ctx).Error("Server - there was an error calling Run on router", helpers.Error(err))
		return err
	}

	return nil
}
