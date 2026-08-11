package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kubescape/backend/pkg/servicediscovery"
	"github.com/kubescape/backend/pkg/servicediscovery/schema"
	v3 "github.com/kubescape/backend/pkg/servicediscovery/v3"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/spf13/viper"
)

type timeoutBoundServiceDiscoveryGetter struct {
	schema.IServiceDiscoveryClient
	httpClient *http.Client
}

func (g timeoutBoundServiceDiscoveryGetter) Get() (io.Reader, error) {
	response, err := g.httpClient.Get(g.GetServiceDiscoveryUrl())
	if err != nil {
		return nil, err
	}

	if response.StatusCode < 200 || response.StatusCode >= 300 {
		_ = response.Body.Close()
		return nil, fmt.Errorf("server (%s) responded: %v", g.GetHost(), response.StatusCode)
	}
	return response.Body, nil
}

// CVEMatchingMode controls how kubevuln configures Grype's CPE-based matching.
type CVEMatchingMode string

const (
	// CVEMatchingOff disables CPE matching everywhere (Grype defaults).
	// Equivalent to the legacy useDefaultMatchers: true.
	CVEMatchingOff CVEMatchingMode = "off"
	// CVEMatchingOn enables CPE matching everywhere.
	// Equivalent to the legacy useDefaultMatchers: false.
	CVEMatchingOn CVEMatchingMode = "on"
	// CVEMatchingAdaptive enables CPE matching everywhere except for images
	// from trusted vendors (identified via Grype's distro detection), where
	// Grype defaults apply for that scan. This is the default mode.
	CVEMatchingAdaptive CVEMatchingMode = "adaptive"
)

// defaultTrustedVendors are the distro identifiers (as recognised by Grype's
// distro detection) of vendors that maintain authoritative vulnerability feeds
// already integrated into the Grype DB. For these images CPE name-fuzzing only
// adds false positives, so adaptive mode falls back to Grype defaults.
var defaultTrustedVendors = []string{"echo", "chainguard", "wolfi", "minimos"}

type Config struct {
	AccountID               string            `mapstructure:"accountID"`
	ClusterName             string            `mapstructure:"clusterName"`
	KeepLocal               bool              `mapstructure:"keepLocal"`
	ListingURL              string            `mapstructure:"listingURL"`
	MaxImageSize            int64             `mapstructure:"maxImageSize"`
	MaxSBOMSize             int               `mapstructure:"maxSBOMSize"`
	Namespace               string            `mapstructure:"namespace"`
	NodeSbomGeneration      bool              `mapstructure:"nodeSbomGeneration"`
	PartialRelevancy        bool              `mapstructure:"partialRelevancy"`
	ScanConcurrency         int               `mapstructure:"scanConcurrency"`
	ProxyRegistryMap        map[string]string `mapstructure:"proxyRegistryMap"`
	ScanEmbeddedSboms       bool              `mapstructure:"scanEmbeddedSBOMs"`
	ScanTimeout             time.Duration     `mapstructure:"scanTimeout"`
	ScannerReadinessTimeout time.Duration     `mapstructure:"scannerReadinessTimeout"`
	ShutdownTimeout         time.Duration     `mapstructure:"shutdownTimeout"`
	RiskAcceptance          bool              `mapstructure:"riskAcceptance"`
	Storage                 bool              `mapstructure:"storage"`
	StoreFilteredSbom       bool              `mapstructure:"storeFilteredSbom"`
	UseDefaultMatchers      bool              `mapstructure:"useDefaultMatchers"` // Deprecated: use CVEMatchingMode. Kept for backward compatibility (true -> off, false -> on).
	CVEMatchingMode         CVEMatchingMode   `mapstructure:"cveMatchingMode"`
	TrustedVendors          []string          `mapstructure:"trustedVendors"` // distro slugs trusted in adaptive mode; empty/unset reverts to defaultTrustedVendors
	VexGeneration           bool              `mapstructure:"vexGeneration"`
}

// LoadConfig reads configuration from file or environment variables.
func LoadConfig(path string) (Config, error) {
	// set key delimiter to :: to allow nested config when using JSON files
	v := viper.NewWithOptions(viper.KeyDelimiter("::"))
	v.AddConfigPath(path)
	v.SetConfigName("clusterData")
	v.SetConfigType("json")

	v.SetDefault("listingURL", "https://grype.anchore.io/databases")
	v.SetDefault("maxImageSize", 512*1024*1024)
	v.SetDefault("maxSBOMSize", 20*1024*1024)
	v.SetDefault("scanConcurrency", 1)
	v.SetDefault("scanTimeout", 5*time.Minute)
	v.SetDefault("scannerReadinessTimeout", 60*time.Second)
	// cmd/http/main.go spends up to 5s on the HTTP server's own Shutdown before this
	// phase (the worker-pool drain, see controllers.HTTPController.Shutdown) even
	// starts. 20s here keeps the combined worst case at 25s, safely under Kubernetes'
	// typical terminationGracePeriodSeconds (30s default), so the drain has a chance
	// to log an explicit abandonment before the kubelet SIGKILLs the process, instead
	// of silently running out the clock past the grace period.
	v.SetDefault("shutdownTimeout", 20*time.Second)
	v.SetDefault("vexGeneration", false)
	v.SetDefault("namespace", "kubescape")
	v.SetDefault("scanEmbeddedSBOMs", false)
	// NB: cveMatchingMode is intentionally NOT given a viper default. viper
	// reports SetDefault keys as "set" via IsSet, which would defeat the
	// presence detection used below for backward compatibility. The default
	// (adaptive) is applied in code instead.

	v.AutomaticEnv()

	err := v.ReadInConfig()
	if err != nil {
		return Config{}, err
	}

	var config Config
	if err = v.Unmarshal(&config); err != nil {
		return Config{}, err
	}

	// Resolve the effective CVE matching mode. An explicit cveMatchingMode
	// always wins. Backward compatibility: when cveMatchingMode is absent but
	// the legacy useDefaultMatchers boolean is set, derive the mode from it
	// (true -> off, false -> on). With neither set, the default is adaptive.
	// Read through viper's getters rather than the unmarshalled struct: with
	// AutomaticEnv, a value supplied purely via environment variable is visible
	// to IsSet/GetString but is NOT populated by Unmarshal, so relying on the
	// struct field here would drop env overrides (and, for the mode, fail
	// validation below).
	switch {
	case v.IsSet("cveMatchingMode"):
		config.CVEMatchingMode = CVEMatchingMode(v.GetString("cveMatchingMode"))
	case v.IsSet("useDefaultMatchers"):
		if v.GetBool("useDefaultMatchers") {
			config.CVEMatchingMode = CVEMatchingOff
		} else {
			config.CVEMatchingMode = CVEMatchingOn
		}
	default:
		config.CVEMatchingMode = CVEMatchingAdaptive
	}

	switch config.CVEMatchingMode {
	case CVEMatchingOff, CVEMatchingOn, CVEMatchingAdaptive:
		// valid
	default:
		return Config{}, fmt.Errorf("invalid cveMatchingMode %q: must be one of %q, %q, %q",
			config.CVEMatchingMode, CVEMatchingOff, CVEMatchingOn, CVEMatchingAdaptive)
	}

	// Same AutomaticEnv/Unmarshal gap as cveMatchingMode above, but for slice/map
	// fields: Unmarshal silently drops env-only values for []string and
	// map[string]string, so an env-only TRUSTEDVENDORS/PROXYREGISTRYMAP would
	// otherwise be lost. Read through viper's getters when the field was
	// actually set (via file or env) rather than trusting the unmarshalled
	// struct field alone.
	if v.IsSet("trustedVendors") {
		config.TrustedVendors = trustedVendorsFromViper(v)
	}
	if len(config.TrustedVendors) == 0 {
		// copy to avoid aliasing the package-level default slice
		config.TrustedVendors = append([]string{}, defaultTrustedVendors...)
	}

	if v.IsSet("proxyRegistryMap") {
		config.ProxyRegistryMap = v.GetStringMapString("proxyRegistryMap")
	}

	return config, nil
}

// trustedVendorsFromViper resolves trustedVendors regardless of whether it came
// from the JSON config file (already a []interface{}, handled fine by
// GetStringSlice) or from a TRUSTEDVENDORS environment variable (a plain string,
// which GetStringSlice does not split): env values are a comma-separated list,
// e.g. TRUSTEDVENDORS=echo,chainguard.
func trustedVendorsFromViper(v *viper.Viper) []string {
	raw, ok := v.Get("trustedVendors").(string)
	if !ok {
		return v.GetStringSlice("trustedVendors")
	}
	var vendors []string
	for _, part := range strings.Split(raw, ",") {
		if part = strings.TrimSpace(part); part != "" {
			vendors = append(vendors, part)
		}
	}
	return vendors
}

type clusterDataBackendServicesConfig struct {
	BackendOpenAPI       string `json:"backendOpenAPI"`
	EventReceiverRestURL string `json:"eventReceiverRestURL"`
}

// normalizeServiceURL returns a base service URL (scheme + host), dropping any path.
func normalizeServiceURL(input string) string {
	normalized := strings.TrimSpace(input)
	if normalized == "" {
		return ""
	}

	parsed, err := url.Parse(normalized)
	if err == nil && parsed.Host != "" {
		scheme := parsed.Scheme
		if scheme == "" {
			scheme = "https"
		}
		return (&url.URL{Scheme: scheme, Host: parsed.Host}).String()
	}

	hasHTTP := strings.HasPrefix(normalized, "http://")
	normalized = strings.TrimPrefix(normalized, "http://")
	normalized = strings.TrimPrefix(normalized, "https://")
	normalized, _, _ = strings.Cut(normalized, "/")
	if normalized == "" {
		return ""
	}
	if hasHTTP {
		return "http://" + normalized
	}
	return "https://" + normalized
}

func loadBackendServicesFromClusterData(configDir string) (schema.IBackendServices, error) {
	filePath := filepath.Join(configDir, "clusterData.json")
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var clusterData clusterDataBackendServicesConfig
	if err := json.Unmarshal(content, &clusterData); err != nil {
		return nil, fmt.Errorf("failed to parse %s: %w", filePath, err)
	}

	apiServerURL := normalizeServiceURL(clusterData.BackendOpenAPI)
	reportReceiverURL := normalizeServiceURL(clusterData.EventReceiverRestURL)

	if apiServerURL == "" || reportReceiverURL == "" {
		return nil, fmt.Errorf("no static backend URLs in %s", filePath)
	}

	return &v3.ServicesV3{
		ApiServerUrl:         apiServerURL,
		EventReceiverHttpUrl: reportReceiverURL,
	}, nil
}

// LoadBackendServicesConfig loads backend service URLs from configDir/services.json if
// present. When services.json is absent, it first attempts API_URL service discovery and
// falls back to static URLs in clusterData.json.
func LoadBackendServicesConfig(configDir, apiURL string) (schema.IBackendServices, error) {
	filePath := filepath.Join(configDir, "services.json")
	if _, err := os.Stat(filePath); err == nil {
		return servicediscovery.GetServices(v3.NewServiceDiscoveryFileV3(filePath))
	}

	if apiURL == "" {
		if services, err := loadBackendServicesFromClusterData(configDir); err == nil {
			return services, nil
		}
		return nil, fmt.Errorf("no service configuration: provide %s/services.json, set API_URL, or set backendOpenAPI/eventReceiverRestURL in clusterData.json", configDir)
	}

	client, err := v3.NewServiceDiscoveryClientV3(apiURL)
	if err != nil {
		return nil, err
	}
	services, err := loadBackendServicesFromAPI(client, &http.Client{Timeout: 30 * time.Second})
	if err == nil {
		return services, nil
	}

	fallbackServices, fallbackErr := loadBackendServicesFromClusterData(configDir)
	if fallbackErr == nil {
		logger.L().Warning("API_URL service discovery failed, falling back to static backend URLs from clusterData.json",
			helpers.Error(err))
		return fallbackServices, nil
	}
	return nil, errors.Join(err, fallbackErr)
}

func loadBackendServicesFromAPI(client schema.IServiceDiscoveryClient, httpClient *http.Client) (schema.IBackendServices, error) {
	return servicediscovery.GetServices(timeoutBoundServiceDiscoveryGetter{
		IServiceDiscoveryClient: client,
		httpClient:              httpClient,
	})
}
