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
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/kubevuln/adapters"
	v1 "github.com/kubescape/kubevuln/adapters/v1"
	"github.com/kubescape/kubevuln/config"
	"github.com/kubescape/kubevuln/controllers"
	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/kubevuln/core/ports"
	"github.com/kubescape/kubevuln/core/services"
	"github.com/kubescape/kubevuln/internal/metrics"
	"github.com/kubescape/kubevuln/internal/tools"
	sbomscanner "github.com/kubescape/kubevuln/pkg/sbomscanner/v1"
	"github.com/kubescape/kubevuln/repositories"
	"go.opentelemetry.io/contrib/instrumentation/github.com/gin-gonic/gin/otelgin"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	typedcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/record"
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
	scanMode := domain.ScanModeInProcess
	if socketPath := os.Getenv("SBOM_SCANNER_SOCKET"); socketPath != "" {
		logger.L().Info("connecting to SBOM scanner sidecar", helpers.String("socket", socketPath))
		scannerClient, err := sbomscanner.NewSBOMScannerClient(ctx, socketPath, c.ScannerReadinessTimeout)
		if err != nil {
			if ctx.Err() != nil {
				logger.L().Info("shutdown requested while waiting for SBOM scanner sidecar")
				return
			}
			logger.L().Error("SBOM scanner sidecar not ready after readiness timeout, falling back to in-process Syft",
				helpers.Error(err), helpers.String("readinessTimeout", c.ScannerReadinessTimeout.String()))
			sbomAdapter = v1.NewSyftAdapter(c.ScanTimeout, c.MaxImageSize, c.MaxSBOMSize, c.ScanEmbeddedSboms, c.ProxyRegistryMap)
		} else {
			memoryLimit := os.Getenv("SCANNER_MEMORY_LIMIT")
			sbomAdapter = v1.NewSidecarSBOMAdapter(scannerClient, c.ScanTimeout, c.MaxImageSize, c.MaxSBOMSize, c.ScanEmbeddedSboms, memoryLimit, c.ProxyRegistryMap)
			scanMode = domain.ScanModeSidecar
		}
	} else {
		sbomAdapter = v1.NewSyftAdapter(c.ScanTimeout, c.MaxImageSize, c.MaxSBOMSize, c.ScanEmbeddedSboms, c.ProxyRegistryMap)
	}
	cveAdapter := v1.NewGrypeAdapter(c.ListingURL, c.CVEMatchingMode, c.TrustedVendors)

	// SecurityException CRD integration requires storage and riskAcceptance RBAC
	var seRepo ports.SecurityExceptionRepository
	var eventRecorder record.EventRecorder
	riskAcceptanceActive := isRiskAcceptanceActive(storage, c.RiskAcceptance)
	if riskAcceptanceActive {
		seRepo = storage
		logger.L().Info("SecurityException CRD integration enabled")

		// Event recording is best-effort: a confirmed suppression is always logged
		// regardless, so a missing/broken k8s config here should not block startup.
		if k8sConfig := k8sinterface.GetK8sConfig(); k8sConfig != nil {
			if clientset, err := kubernetes.NewForConfig(k8sConfig); err != nil {
				logger.L().Ctx(ctx).Warning("failed to build k8s clientset for SecurityException events", helpers.Error(err))
			} else {
				broadcaster := record.NewBroadcaster()
				broadcaster.StartStructuredLogging(0)
				broadcaster.StartRecordingToSink(&typedcorev1.EventSinkImpl{Interface: clientset.CoreV1().Events("")})
				eventRecorder = broadcaster.NewRecorder(runtime.NewScheme(), corev1.EventSource{Component: "kubevuln"})
			}
		} else {
			logger.L().Warning("failed to get k8s config for SecurityException events")
		}
	} else {
		// storage alone means an operator has SecurityException/ClusterSecurityException CRDs
		// reachable but riskAcceptance unset -- without this log, that combination silently
		// no-ops (see #562): the NoOpSecurityExceptionRepository below always returns empty
		// results, indistinguishable at runtime from "no CRDs exist in this cluster".
		if storage != nil {
			logger.L().Warning("SecurityException CRD integration disabled: storage is enabled but riskAcceptance is not set; SecurityException/ClusterSecurityException CRDs will not be applied")
		}
		seRepo = &repositories.NoOpSecurityExceptionRepository{}
	}

	var platform ports.Platform
	if c.KeepLocal {
		platform = adapters.NewMockPlatform(true, seRepo)
	} else {
		apiURL := os.Getenv("API_URL")
		backendServices, err := config.LoadBackendServicesConfig(configDir, apiURL)
		if err != nil {
			logger.L().Ctx(ctx).Fatal("load services error", helpers.Error(err))
		}
		logger.L().Info("loaded backend services", helpers.String("ApiServerUrl", backendServices.GetApiServerUrl()), helpers.String("ReportReceiverHttpUrl", backendServices.GetReportReceiverHttpUrl()))
		backendAdapter := v1.NewBackendAdapter(credentials.Account, backendServices.GetApiServerUrl(), backendServices.GetReportReceiverHttpUrl(), credentials.AccessKey, seRepo)
		platform = backendAdapter
	}
	var relevancyProvider ports.Relevancy
	if storage != nil {
		relevancyProvider = v1.NewContainerProfileAdapter(storage)
	} else {
		relevancyProvider = adapters.NewMockRelevancyAdapter()
	}
	service := services.NewScanService(sbomAdapter, storage, cveAdapter, storage, platform, relevancyProvider, c.Storage, c.VexGeneration, !c.NodeSbomGeneration, c.StoreFilteredSbom, c.PartialRelevancy)
	if eventRecorder != nil {
		service.SetEventRecorder(eventRecorder)
	}
	controller := controllers.NewHTTPController(service, c.ScanConcurrency)
	controller = controller.WithDiagnostics(func(diagCtx context.Context) domain.Diagnostics {
		return domain.Diagnostics{
			ScanMode:                scanMode,
			SBOMCreatorVersion:      sbomAdapter.Version(),
			CVEScannerVersion:       cveAdapter.Version(),
			CVEDBVersion:            cveAdapter.DBVersion(diagCtx),
			ScanTimeout:             c.ScanTimeout.String(),
			ScannerReadinessTimeout: c.ScannerReadinessTimeout.String(),
			StorageEnabled:          c.Storage,
			RiskAcceptanceEnabled:   riskAcceptanceActive,
		}
	})

	m, err := metrics.New()
	if err != nil {
		logger.L().Ctx(ctx).Fatal("metrics initialization error", helpers.Error(err))
	}
	service.SetMetrics(m)
	controller, err = controller.WithMetrics(m)
	if err != nil {
		logger.L().Ctx(ctx).Fatal("metrics registration error", helpers.Error(err))
	}

	// Best-effort startup sweep: reclaim stereoscope temp dirs orphaned by previous process
	// invocations killed by SIGKILL (OOM kill, or terminationGracePeriodSeconds exceeded)
	// before their defer-based cleanup could run. The threshold is ScanTimeout: the main
	// process and the SBOM-scanner sidecar run in the same Pod on the same machine (same
	// kernel clock), so no clock-skew margin is needed, and a dir idle longer than
	// ScanTimeout can only belong to a dead or already-timed-out scan.
	if removed, err := tools.CleanupStaleTempDirs(os.TempDir(), "stereoscope-", c.ScanTimeout); err != nil {
		logger.L().Ctx(ctx).Warning("startup temp dir sweep error",
			helpers.Error(err),
			helpers.Int("removed", removed))
	} else if removed > 0 {
		logger.L().Ctx(ctx).Info("startup temp dir sweep complete",
			helpers.Int("removed", removed))
	}

	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(gin.Recovery())

	router.GET("/v1/liveness", controller.Alive)
	router.GET("/v1/readiness", controller.Ready)
	router.GET("/v1/diagnostics", controller.Diagnostics)
	router.GET("/metrics", gin.WrapH(m.Handler()))

	group := router.Group(apis.VulnerabilityScanCommandVersion)
	{
		group.Use(otelgin.Middleware("kubevuln-svc"))
		group.POST("/"+apis.SBOMCalculationCommandPath, controller.GenerateSBOM)
		group.POST("/"+apis.ApplicationProfileScanCommandPath, controller.ScanCP)
		group.POST("/"+apis.ContainerScanCommandPath, controller.ScanCVE)
		group.POST("/"+apis.RegistryScanCommandPath, controller.ScanRegistry)
		group.GET("/scanStatus/:jobID", controller.ScanStatus)
	}

	srv := &http.Server{
		Addr:              ":8080",
		Handler:           router,
		ReadHeaderTimeout: 10 * time.Second,
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

	// Give the HTTP server up to 5 seconds to finish in-flight requests. This must be
	// derived from context.Background(), not the signal ctx above: that one is already
	// Done() by this point (we only got here via <-ctx.Done()), so deriving from it
	// would hand srv.Shutdown an already-expired context and return immediately.
	srvCtx, srvCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer srvCancel()
	if err := srv.Shutdown(srvCtx); err != nil {
		// Log and continue rather than exit: a failed/timed-out HTTP shutdown must not
		// skip the worker-pool drain below, since that's where actual queued/running
		// scan work would otherwise be silently lost (#467).
		logger.L().Ctx(srvCtx).Error("server shutdown error", helpers.Error(err))
	}

	// Purging the controller worker queue, bounded by ShutdownTimeout so this
	// doesn't silently run past the pod's terminationGracePeriodSeconds
	controller.Shutdown(c.ShutdownTimeout)

	if err := m.Shutdown(srvCtx); err != nil {
		logger.L().Ctx(srvCtx).Error("metrics provider shutdown error", helpers.Error(err))
	}

	logger.L().Info("kubevuln exiting")
}

// isRiskAcceptanceActive reports whether SecurityException/ClusterSecurityException
// CRD integration is actually wired up, as opposed to the raw --risk-acceptance
// config flag: integration also requires storage to be configured, since without
// it seRepo falls back to NoOpSecurityExceptionRepository regardless of the flag.
func isRiskAcceptanceActive(storage *repositories.APIServerStore, riskAcceptance bool) bool {
	return storage != nil && riskAcceptance
}
