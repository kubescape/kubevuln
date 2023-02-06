package main

import (
	"context"
	"net/url"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubevuln/adapters"
	"github.com/kubescape/kubevuln/adapters/v1"
	"github.com/kubescape/kubevuln/controllers"
	"github.com/kubescape/kubevuln/core/services"
	"github.com/kubescape/kubevuln/repositories"
	"go.opentelemetry.io/contrib/instrumentation/github.com/gin-gonic/gin/otelgin"
)

func main() {
	ctx := context.Background()
	// to enable otel, set OTEL_COLLECTOR_SVC=otel-collector:4317
	if otelHost, present := os.LookupEnv("OTEL_COLLECTOR_SVC"); present {
		ctx = logger.InitOtel("kubevuln",
			os.Getenv("RELEASE"),
			os.Getenv("ACCOUNT_ID"),
			url.URL{Host: otelHost})
		defer logger.ShutdownOtel(ctx)
	}

	repository := repositories.NewMemoryStorage() // TODO add real storage
	sbomAdapter := v1.NewSyftAdapter()
	cveAdapter, _ := v1.NewGrypeAdapter(ctx)
	platform := adapters.NewMockPlatform() // TODO add real platform
	service := services.NewScanService(sbomAdapter, repository, cveAdapter, repository, platform)
	controller := controllers.NewHTTPController(service)

	router := gin.Default()
	router.Use(otelgin.Middleware("kubevuln-svc"))

	router.GET("/v1/ready", controller.Ready)
	router.POST("/v1/generateSBOM", controller.GenerateSBOM)
	router.POST("/v1/scanImage", controller.ScanCVE)

	logger.L().Ctx(ctx).Fatal("router error", helpers.Error(router.Run()))
}
