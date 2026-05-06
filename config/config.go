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
	UseDefaultMatchers bool              `mapstructure:"useDefaultMatchers"`
	VexGeneration      bool              `mapstructure:"vexGeneration"`
}

// LoadConfig reads configuration from file or environment variables.
func LoadConfig(path string) (Config, error) {
	viper.AddConfigPath(path)
	viper.SetConfigName("clusterData")
	viper.SetConfigType("json")

	viper.SetDefault("listingURL", "https://grype.anchore.io/databases")
	viper.SetDefault("maxImageSize", 512*1024*1024)
	viper.SetDefault("maxSBOMSize", 20*1024*1024)
	viper.SetDefault("scanConcurrency", 1)
	viper.SetDefault("scanTimeout", 5*time.Minute)
	viper.SetDefault("vexGeneration", false)
	viper.SetDefault("namespace", "kubescape")
	viper.SetDefault("scanEmbeddedSBOMs", false)

	viper.AutomaticEnv()

	err := viper.ReadInConfig()
	if err != nil {
		return Config{}, err
	}

	var config Config
	err = viper.Unmarshal(&config)
	return config, err
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
