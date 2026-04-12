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
	"github.com/kubescape/backend/pkg/utils"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubevuln/adapters"
	v1 "github.com/kubescape/kubevuln/adapters/v1"
	"github.com/kubescape/kubevuln/config"
	"github.com/kubescape/kubevuln/controllers"
	"github.com/kubescape/kubevuln/core/ports"
	"github.com/kubescape/kubevuln/core/services"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
	sbomscanner "github.com/kubescape/kubevuln/pkg/sbomscanner/v1"
	"github.com/kubescape/kubevuln/repositories"
	"go.opentelemetry.io/contrib/instrumentation/github.com/gin-gonic/gin/otelgin"
)

func main() {
	ctx := context.Background()

	configDir := "/etc/config"
	if envPath := os.Getenv("CONFIG_DIR"); envPath != "" {
		configDir = envPath
	}

	c, err := config.LoadConfig(configDir)
	if err != nil {
		logger.L().Ctx(ctx).Fatal("load config error", helpers.Error(err))
	}

	var credentials *utils.Credentials
	if credentials, err = utils.LoadCredentialsFromFile("/etc/credentials"); err != nil {
		logger.L().Ctx(ctx).Error("failed to load credentials", helpers.Error(err))
		credentials = &utils.Credentials{}
	} else {
		logger.L().Info("credentials loaded",
			helpers.Int("accessKeyLength", len(credentials.AccessKey)),
			helpers.Int("accountLength", len(credentials.Account)))
	}

	// to enable otel, set OTEL_COLLECTOR_SVC=otel-collector:4317
	if otelHost, present := os.LookupEnv("OTEL_COLLECTOR_SVC"); present {
		ctx = logger.InitOtel("kubevuln",
			os.Getenv("RELEASE"),
			credentials.Account,
			c.ClusterName,
			url.URL{Host: otelHost})
		defer logger.ShutdownOtel(ctx)
	}

	// modify context to listen to interrupt signals from the OS.
	ctx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	var storage *repositories.APIServerStore
	if c.Storage {
		storage, err = repositories.NewAPIServerStorage(c.Namespace)
		if err != nil {
			logger.L().Ctx(ctx).Fatal("storage initialization error", helpers.Error(err))
		}
	}
	var sbomAdapter ports.SBOMCreator
	if socketPath := os.Getenv("SBOM_SCANNER_SOCKET"); socketPath != "" {
		logger.L().Info("connecting to SBOM scanner sidecar", helpers.String("socket", socketPath))
		scannerClient, err := sbomscanner.NewSBOMScannerClient(socketPath)
		if err != nil {
			logger.L().Warning("failed to connect to SBOM scanner sidecar, falling back to in-process Syft",
				helpers.Error(err))
			sbomAdapter = v1.NewSyftAdapter(c.ScanTimeout, c.MaxImageSize, c.MaxSBOMSize, c.ScanEmbeddedSboms)
		} else {
			memoryLimit := os.Getenv("SCANNER_MEMORY_LIMIT")
			sbomAdapter = v1.NewSidecarSBOMAdapter(scannerClient, c.ScanTimeout, c.MaxImageSize, c.MaxSBOMSize, c.ScanEmbeddedSboms, memoryLimit)
		}
	} else {
		sbomAdapter = v1.NewSyftAdapter(c.ScanTimeout, c.MaxImageSize, c.MaxSBOMSize, c.ScanEmbeddedSboms)
	}
	cveAdapter := v1.NewGrypeAdapter(c.ListingURL, c.UseDefaultMatchers)
	var platform ports.Platform
	if c.KeepLocal {
		platform = adapters.NewMockPlatform(true)
	} else {
		backendServices, err := config.LoadBackendServicesConfig("/etc/config")
		if err != nil {
			logger.L().Ctx(ctx).Fatal("load services error", helpers.Error(err))
		}
		logger.L().Info("loaded backend services", helpers.String("ApiServerUrl", backendServices.GetApiServerUrl()), helpers.String("ReportReceiverHttpUrl", backendServices.GetReportReceiverHttpUrl()))
		backendAdapter := v1.NewBackendAdapter(credentials.Account, backendServices.GetApiServerUrl(), backendServices.GetReportReceiverHttpUrl(), credentials.AccessKey)

		// Wire up CRD-based SecurityException integration (optional — failures are non-fatal)
		if restConfig, err := rest.InClusterConfig(); err != nil {
			logger.L().Ctx(ctx).Warning("failed to get in-cluster config for SecurityException CRDs", helpers.Error(err))
		} else if dynClient, err := dynamic.NewForConfig(restConfig); err != nil {
			logger.L().Ctx(ctx).Warning("failed to create dynamic client for SecurityException CRDs", helpers.Error(err))
		} else {
			seAdapter := v1.NewSecurityExceptionAdapter(dynClient)
			backendAdapter.SetSecurityExceptionAdapter(seAdapter)
			logger.L().Info("SecurityException CRD integration enabled")
		}

		platform = backendAdapter
	}
	relevancyProvider := v1.NewContainerProfileAdapter(storage)
	service := services.NewScanService(sbomAdapter, storage, cveAdapter, storage, platform, relevancyProvider, c.Storage, c.VexGeneration, !c.NodeSbomGeneration, c.StoreFilteredSbom, c.PartialRelevancy)
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
		group.POST("/"+apis.ApplicationProfileScanCommandPath, controller.ScanCP)
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
