package listener

import (
	"context"

	"github.com/gin-gonic/gin"
	apiv1 "github.com/kubescape/kubevuln/pkg/api/v1"
	"github.com/kubescape/kubevuln/pkg/app"
	"github.com/kubescape/kubevuln/pkg/repository"
	"go.opentelemetry.io/contrib/instrumentation/github.com/gin-gonic/gin/otelgin"
)

func SetupHTTPListener(ctx context.Context) error {
	// create storage dependency
	storage := repository.NewStorage()

	// create router dependency
	router := gin.Default()
	router.Use(otelgin.Middleware("kubevuln-svc"))

	// create cve service
	cveService := apiv1.NewCVEService(storage)

	// create sbom service
	sbomService := apiv1.NewSBOMService(storage)

	// create scanner service
	scannerService := apiv1.NewScannerService()

	server := app.NewServer(router, cveService, sbomService, scannerService)

	return server.Run(ctx)
}
