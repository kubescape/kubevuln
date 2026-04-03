package config

import (
	"time"

	"github.com/kubescape/backend/pkg/servicediscovery"
	"github.com/kubescape/backend/pkg/servicediscovery/schema"
	v3 "github.com/kubescape/backend/pkg/servicediscovery/v3"
	"github.com/spf13/viper"
)

type Config struct {
	AccountID          string        `mapstructure:"accountID"`
	ClusterName        string        `mapstructure:"clusterName"`
	KeepLocal          bool          `mapstructure:"keepLocal"`
	ListingURL         string        `mapstructure:"listingURL"`
	MaxImageSize       int64         `mapstructure:"maxImageSize"`
	MaxSBOMSize        int           `mapstructure:"maxSBOMSize"`
	Namespace          string        `mapstructure:"namespace"`
	NodeSbomGeneration bool          `mapstructure:"nodeSbomGeneration"`
	PartialRelevancy   bool          `mapstructure:"partialRelevancy"`
	ScanConcurrency    int           `mapstructure:"scanConcurrency"`
	ScanEmbeddedSboms  bool          `mapstructure:"scanEmbeddedSBOMs"`
	ScanTimeout        time.Duration `mapstructure:"scanTimeout"`
	Storage            bool          `mapstructure:"storage"`
	StoreFilteredSbom  bool          `mapstructure:"storeFilteredSbom"`
	UseDefaultMatchers bool          `mapstructure:"useDefaultMatchers"`
	VexGeneration      bool          `mapstructure:"vexGeneration"`
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

// LoadBackendServicesConfig queries the API for backend service URLs.
func LoadBackendServicesConfig(apiURL string) (schema.IBackendServices, error) {
	client, err := v3.NewServiceDiscoveryClientV3(apiURL)
	if err != nil {
		return nil, err
	}
	return servicediscovery.GetServices(client)
}
