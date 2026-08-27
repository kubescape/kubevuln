package domain

// Diagnostics reports the SBOM/CVE scan configuration that was resolved at startup,
// so operators can query which mode and versions a running pod is actually using
// instead of inferring it from logs. It intentionally excludes credentials and any
// other secret-derived configuration.
type Diagnostics struct {
	ScanMode                string `json:"scanMode"`
	SBOMCreatorVersion      string `json:"sbomCreatorVersion"`
	CVEScannerVersion       string `json:"cveScannerVersion"`
	CVEDBVersion            string `json:"cveDBVersion"`
	ScanTimeout             string `json:"scanTimeout"`
	ScannerReadinessTimeout string `json:"scannerReadinessTimeout"`
	StorageEnabled          bool   `json:"storageEnabled"`
	RiskAcceptanceEnabled   bool   `json:"riskAcceptanceEnabled"`
	// QueueDepth is the number of scan jobs currently waiting in the HTTP controller's
	// worker pool, the same value backing the kubevuln_worker_pool_queue_depth metric
	// (see controllers.HTTPController.WithMetrics). Surfacing it here lets operators read
	// current backlog directly instead of having to query Prometheus.
	QueueDepth int `json:"queueDepth"`
}

const (
	// ScanModeSidecar indicates SBOM generation runs through the sbom-scanner sidecar.
	ScanModeSidecar = "sidecar"
	// ScanModeInProcess indicates SBOM generation runs in-process via Syft.
	ScanModeInProcess = "in-process"
)
