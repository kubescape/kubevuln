package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/armosec/armoapi-go/apis"
	"github.com/gin-gonic/gin"
	"github.com/kubescape/backend/pkg/utils"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/go-logger/otelsetup"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/kubevuln/adapters"
	v1 "github.com/kubescape/kubevuln/adapters/v1"
	"github.com/kubescape/kubevuln/config"
	"github.com/kubescape/kubevuln/controllers"
	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/kubevuln/core/ports"
	"github.com/kubescape/kubevuln/core/services"
	"github.com/kubescape/kubevuln/internal/metrics"
	"github.com/kubescape/kubevuln/internal/telemetry"
	"github.com/kubescape/kubevuln/internal/tools"
	sbomscanner "github.com/kubescape/kubevuln/pkg/sbomscanner/v1"
	"github.com/kubescape/kubevuln/repositories"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
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
		credentials = &utils.Credentials{}
	}

	if credentials.Account, err = resolveAccountID(credentials.Account, c.AccountID, c.KeepLocal); err != nil {
		logger.L().Ctx(ctx).Fatal("account identifier error", helpers.Error(err))
	}

	// Telemetry discovery is optional and bounded; core backend discovery remains separate.
	discoveryErr := telemetry.ConfigureEndpoint(ctx, func(discoveryCtx context.Context) (string, error) {
		if c.KeepLocal {
			return "", nil
		}
		return config.DiscoverTelemetry(discoveryCtx, os.Getenv("API_URL"))
	})
	providerConfig := otelsetup.ProviderConfig{ServiceName: "kubevuln", ServiceVersion: os.Getenv("RELEASE"), AccountID: credentials.Account, AccessKey: credentials.AccessKey, ClusterName: c.ClusterName, Namespace: c.Namespace, PodName: os.Getenv("POD_NAME"), NodeName: os.Getenv("NODE_NAME")}
	shutdownTelemetry, telemetryErr := telemetry.Init(ctx, providerConfig)
	defer func() {
		flushCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = shutdownTelemetry(flushCtx)
	}()
	metricOptions := []sdkmetric.Option{sdkmetric.WithResource(resource.NewSchemaless(metrics.ResourceAttributes(providerConfig)...))}
	if reader, exportErr := metrics.OTLPReader(ctx, providerConfig); exportErr != nil {
		logger.L().Warning("operational metric exporter unavailable")
	} else if reader != nil {
		metricOptions = append(metricOptions, sdkmetric.WithReader(reader))
	}
	m, err := metrics.New(metricOptions...)
	if err != nil {
		logger.L().Ctx(ctx).Fatal("metrics initialization error", helpers.Error(err))
	}
	// Reconstruct the configured local logger after providers exist. Its OTLP branch
	// is denied export by the operational scope allowlist; stdout behavior is retained.
	logger.InitDefaultLogger()
	if discoveryErr != nil {
		logger.L().Warning("operational telemetry discovery unavailable")
	}
	if telemetryErr != nil {
		logger.L().Warning("operational telemetry initialization unavailable")
	}
	telemetry.Lifecycle(ctx, "kubevuln.startup")

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
			sidecarAdapter := v1.NewSidecarSBOMAdapter(scannerClient, c.ScanTimeout, c.MaxImageSize, c.MaxSBOMSize, c.ScanEmbeddedSboms, memoryLimit, c.ProxyRegistryMap)
			if status := scannerStatus(ctx, c.Namespace); status != nil {
				sidecarAdapter.SetScannerStatus(status)
			}
			sbomAdapter = sidecarAdapter
			scanMode = domain.ScanModeSidecar
		}
	} else {
		sbomAdapter = v1.NewSyftAdapter(c.ScanTimeout, c.MaxImageSize, c.MaxSBOMSize, c.ScanEmbeddedSboms, c.ProxyRegistryMap)
	}
	sbomAdapter, err = configureSBOMReuse(c, sbomAdapter)
	if err != nil {
		logger.L().Ctx(ctx).Fatal("SBOM reuse configuration error", helpers.Error(err))
	}
	cveAdapter := v1.NewGrypeAdapter(c.ListingURL, c.CVEMatchingMode, c.TrustedVendors)

	// SecurityException CRD integration requires storage and riskAcceptance RBAC
	var seRepo ports.SecurityExceptionRepository
	var eventRecorder record.EventRecorder
	riskAcceptanceActive := isRiskAcceptanceActive(storage, c.RiskAcceptance)
	if riskAcceptanceActive {
		seRepo = storage
		storage.EnableSecurityExceptionCacheInvalidation(ctx)
		storage.EnableLabelsCacheInvalidation(ctx)
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
		backendAdapter := v1.NewBackendAdapter(credentials.Account, backendServices.GetApiServerUrl(), backendServices.GetReportReceiverHttpUrl(), credentials.AccessKey, seRepo).WithClusterName(c.ClusterName)
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
	controller = controller.WithMaxQueueDepth(c.MaxQueueDepth)
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

	service.SetMetrics(m)
	controller, err = controller.WithMetrics(m)
	if err != nil {
		logger.L().Ctx(ctx).Fatal("metrics registration error", helpers.Error(err))
	}

	// Best-effort periodic sweep: reclaim stereoscope temp dirs left behind either by a
	// previous process invocation killed by SIGKILL (OOM kill, or terminationGracePeriodSeconds
	// exceeded) before its defer-based cleanup could run, or by an ordinary (non-crash) registry
	// pull failure in *this* process — stereoscope creates the image temp dir before it has
	// anything to Cleanup() it, so auth failures, transient registry errors, and platform
	// mismatches can all leak one. This process runs for the life of a long-lived pod rather
	// than restarting per scan, so a single startup-only sweep would never reclaim leaks from
	// its own uptime; run it on a recurring interval instead. The threshold is ScanTimeout: the
	// main process and the SBOM-scanner sidecar run in the same Pod on the same machine (same
	// kernel clock), so no clock-skew margin is needed, and a dir idle longer than ScanTimeout
	// can only belong to a dead or already-timed-out scan. ScanTimeout also doubles as the sweep
	// interval, keeping worst-case accumulation bounded to roughly one ScanTimeout's worth of
	// leaks at a time.
	tools.StartPeriodicTempDirSweep(ctx.Done(), os.TempDir(), "stereoscope-", c.ScanTimeout, c.ScanTimeout, func(removed int, err error) {
		if err != nil {
			logger.L().Ctx(ctx).Warning("temp dir sweep error",
				helpers.Error(err),
				helpers.Int("removed", removed))
		} else if removed > 0 {
			logger.L().Ctx(ctx).Info("temp dir sweep complete",
				helpers.Int("removed", removed))
		}
		metrics.RecordTempDirSweep(ctx, metrics.ComponentInProcess, removed)
	})

	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(gin.Recovery())

	router.GET("/v1/liveness", controller.Alive)
	router.GET("/v1/readiness", controller.Ready)
	router.GET("/v1/diagnostics", controller.Diagnostics)
	router.GET("/metrics", gin.WrapH(m.Handler()))

	group := router.Group(apis.VulnerabilityScanCommandVersion)
	{
		// W3C context is extracted by the server wrapper; no per-request spans.
		group.POST("/"+apis.SBOMCalculationCommandPath, controller.GenerateSBOM)
		group.POST("/"+apis.ApplicationProfileScanCommandPath, controller.ScanCP)
		group.POST("/"+apis.ContainerScanCommandPath, controller.ScanCVE)
		group.POST("/"+apis.RegistryScanCommandPath, controller.ScanRegistry)
		group.GET("/scanStatus/:jobID", controller.ScanStatus)
	}

	srv := &http.Server{
		Addr:              ":8080",
		Handler:           telemetry.ExtractHTTP(router),
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
	telemetry.Lifecycle(context.Background(), "kubevuln.shutdown")

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

	// srvCtx's 5s budget is spent by now (controller.Shutdown alone can take up to
	// ShutdownTimeout, 20s by default), so reusing it here would hand the meter
	// provider an already-expired context and skip the final metrics flush.
	metricsCtx, metricsCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer metricsCancel()
	if err := m.Shutdown(metricsCtx); err != nil {
		logger.L().Ctx(metricsCtx).Error("metrics provider shutdown error", helpers.Error(err))
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

// resolveAccountID picks the account identifier every backend report and CVE-exception
// lookup is sent with, preferring credentialsAccount (from /etc/credentials/account,
// normally a mounted Secret) and falling back to configAccountID (clusterData.json's
// accountID field / ACCOUNTID env var) when that's empty. The fallback is what makes
// that documented config field do anything at all: nothing else in this binary reads it
// (see #957).
//
// It returns an error when keepLocal is false and neither source produced a value.
// Without a real account identifier, every backend report would silently carry an
// empty customerGUID instead of kubevuln failing to start the way
// docs/CONFIGURATION.md's "required field" already promises. keepLocal mode never
// talks to the backend, so it's the only case that doesn't need one.
func resolveAccountID(credentialsAccount, configAccountID string, keepLocal bool) (string, error) {
	accountID := credentialsAccount
	if accountID == "" {
		accountID = configAccountID
	}
	if accountID == "" && !keepLocal {
		return "", fmt.Errorf("no account identifier configured: set /etc/credentials/account (normally mounted from a Secret), accountID in clusterData.json, or the ACCOUNTID environment variable -- or set keepLocal to run without reporting to the backend")
	}
	return accountID, nil
}

// scannerStatus gives the sidecar adapter the kubelet's view of the scanner container, so a
// scan lost mid-flight is reported as an OOM kill only when the kubelet recorded one. The
// pod is the one kubevuln runs in: POD_NAME when set, the hostname otherwise.
func scannerStatus(ctx context.Context, namespace string) v1.ScannerStatus {
	k8sConfig := k8sinterface.GetK8sConfig()
	if k8sConfig == nil {
		logger.L().Ctx(ctx).Warning("no k8s config, a lost SBOM scanner sidecar will be reported as unavailable rather than OOM-killed")
		return nil
	}
	clientset, err := kubernetes.NewForConfig(k8sConfig)
	if err != nil {
		logger.L().Ctx(ctx).Warning("failed to build k8s clientset for the SBOM scanner sidecar status", helpers.Error(err))
		return nil
	}
	podName := os.Getenv("POD_NAME")
	if podName == "" {
		if podName, err = os.Hostname(); err != nil {
			logger.L().Ctx(ctx).Warning("failed to resolve the pod name for the SBOM scanner sidecar status", helpers.Error(err))
			return nil
		}
	}
	container := os.Getenv("SBOM_SCANNER_CONTAINER")
	if container == "" {
		container = v1.DefaultScannerContainerName
	}
	status := v1.NewPodScannerStatus(clientset.CoreV1().Pods(namespace), podName, container)
	if err := status.Probe(ctx); err != nil {
		logger.L().Ctx(ctx).Warning("cannot read the pod's container statuses yet, a lost SBOM scanner sidecar will be reported as unavailable rather than OOM-killed until the read works; kubevuln needs get on pods in its namespace",
			helpers.String("pod", podName), helpers.String("container", container), helpers.Error(err))
	}
	return status
}
