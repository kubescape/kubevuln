package main

import (
	"context"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/armosec/armoapi-go/apis"
	"github.com/gin-gonic/gin"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubevuln/adapters"
	v1 "github.com/kubescape/kubevuln/adapters/v1"
	"github.com/kubescape/kubevuln/config"
	"github.com/kubescape/kubevuln/controllers"
	"github.com/kubescape/kubevuln/core/ports"
	"github.com/kubescape/kubevuln/core/services"
	"github.com/kubescape/kubevuln/repositories"
	"go.opentelemetry.io/contrib/instrumentation/github.com/gin-gonic/gin/otelgin"
)

func main() {
	ctx := context.Background()

	c, err := config.LoadConfig("/etc/config")
	if err != nil {
		logger.L().Ctx(ctx).Fatal("load config error", helpers.Error(err))
	}

	// to enable otel, set OTEL_COLLECTOR_SVC=otel-collector:4317
	if otelHost, present := os.LookupEnv("OTEL_COLLECTOR_SVC"); present {
		ctx = logger.InitOtel("kubevuln",
			os.Getenv("RELEASE"),
			c.AccountID,
			c.ClusterName,
			url.URL{Host: otelHost})
		defer logger.ShutdownOtel(ctx)
	}

	// modify context to listen to interrupt signals from the OS.
	ctx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	var storage *repositories.APIServerStore
	if c.Storage {
		storage, err = repositories.NewAPIServerStorage("kubescape")
		if err != nil {
			logger.L().Ctx(ctx).Fatal("storage initialization error", helpers.Error(err))
		}
	}
	sbomAdapter := v1.NewSyftAdapter(c.ScanTimeout, c.MaxImageSize)
	cveAdapter := v1.NewGrypeAdapter()
	var platform ports.Platform
	if c.KeepLocal {
		platform = adapters.NewMockPlatform()
	} else {
		platform = v1.NewArmoAdapter(c.AccountID, c.BackendOpenAPI, c.EventReceiverRestURL)
	}
	service := services.NewScanService(sbomAdapter, storage, cveAdapter, storage, platform, c.Storage)
	controller := controllers.NewHTTPController(service, c.ScanConcurrency)

	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(gin.Recovery())

	router.GET("/v1/liveness", controller.Alive)
	router.GET("/v1/readiness", controller.Ready)

	group := router.Group(apis.VulnerabilityScanCommandVersion)
	{
		group.Use(otelgin.Middleware("kubevuln-svc"))
		group.POST("/"+apis.SBOMCalculationCommandPath, controller.GenerateSBOM)
		group.POST("/"+apis.ContainerScanCommandPath, controller.ScanCVE)
		group.POST("/"+apis.RegistryScanCommandPath, controller.ScanRegistry)
	}

	srv := &http.Server{
		Addr:    ":8080",
		Handler: router,
	}

	// Initializing the server in a goroutine so that
	// it won't block the graceful shutdown handling below
	go func() {
		logger.L().Info("starting server")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.L().Ctx(ctx).Fatal("router error", helpers.Error(err))
		}
	}()

	// Listen for the interrupt signal.
	<-ctx.Done()

	// Restore default behavior on the interrupt signal and notify user of shutdown.
	stop()
	logger.L().Info("shutting down gracefully")

	// modify context to inform the server it has 5 seconds to finish
	// the request it is currently handling
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		logger.L().Ctx(ctx).Fatal("server forced to shutdown", helpers.Error(err))
	}

	// Purging the controller worker queue
	controller.Shutdown()

	logger.L().Info("kubevuln exiting")
}
