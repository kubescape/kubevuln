package config

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/kubescape/backend/pkg/servicediscovery"
	"github.com/kubescape/backend/pkg/servicediscovery/schema"
	v3 "github.com/kubescape/backend/pkg/servicediscovery/v3"
	"github.com/spf13/viper"
)

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
	AccountID          string            `mapstructure:"accountID"`
	ClusterName        string            `mapstructure:"clusterName"`
	KeepLocal          bool              `mapstructure:"keepLocal"`
	ListingURL         string            `mapstructure:"listingURL"`
	MaxImageSize       int64             `mapstructure:"maxImageSize"`
	MaxSBOMSize        int               `mapstructure:"maxSBOMSize"`
	Namespace          string            `mapstructure:"namespace"`
	NodeSbomGeneration bool              `mapstructure:"nodeSbomGeneration"`
	PartialRelevancy   bool              `mapstructure:"partialRelevancy"`
	ScanConcurrency    int               `mapstructure:"scanConcurrency"`
	ProxyRegistryMap   map[string]string `mapstructure:"proxyRegistryMap"`
	ScanEmbeddedSboms  bool              `mapstructure:"scanEmbeddedSBOMs"`
	ScanTimeout        time.Duration     `mapstructure:"scanTimeout"`
	RiskAcceptance     bool              `mapstructure:"riskAcceptance"`
	Storage            bool              `mapstructure:"storage"`
	StoreFilteredSbom  bool              `mapstructure:"storeFilteredSbom"`
	UseDefaultMatchers bool              `mapstructure:"useDefaultMatchers"` // Deprecated: use CVEMatchingMode. Kept for backward compatibility (true -> off, false -> on).
	CVEMatchingMode    CVEMatchingMode   `mapstructure:"cveMatchingMode"`
	TrustedVendors     []string          `mapstructure:"trustedVendors"` // distro slugs trusted in adaptive mode; empty/unset reverts to defaultTrustedVendors
	VexGeneration      bool              `mapstructure:"vexGeneration"`
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

	if len(config.TrustedVendors) == 0 {
		// copy to avoid aliasing the package-level default slice
		config.TrustedVendors = append([]string{}, defaultTrustedVendors...)
	}

	return config, nil
}

// LoadBackendServicesConfig loads backend service URLs from configDir/services.json if
// present, otherwise queries apiURL for live service discovery.
// apiURL must be set explicitly when services.json is absent; no default is applied here.
func LoadBackendServicesConfig(configDir, apiURL string) (schema.IBackendServices, error) {
	filePath := filepath.Join(configDir, "services.json")
	if _, err := os.Stat(filePath); err == nil {
		return servicediscovery.GetServices(v3.NewServiceDiscoveryFileV3(filePath))
	}

	if apiURL == "" {
		return nil, fmt.Errorf("no service configuration: provide %s/services.json or set API_URL", configDir)
	}

	client, err := v3.NewServiceDiscoveryClientV3(apiURL)
	if err != nil {
		return nil, err
	}
	// http.DefaultClient has no timeout by default; cap the startup discovery call.
	http.DefaultClient = &http.Client{Timeout: 30 * time.Second}
	return servicediscovery.GetServices(client)
}
