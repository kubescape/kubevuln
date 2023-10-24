package config

import (
	"path/filepath"
	"time"

	"github.com/kubescape/backend/pkg/servicediscovery"
	"github.com/kubescape/backend/pkg/servicediscovery/schema"
	v1 "github.com/kubescape/backend/pkg/servicediscovery/v1"
	"github.com/spf13/viper"
)

type Config struct {
	AccountID       string        `mapstructure:"accountID"`
	ClusterName     string        `mapstructure:"clusterName"`
	KeepLocal       bool          `mapstructure:"keepLocal"`
	ListingURL      string        `mapstructure:"listingURL"`
	MaxImageSize    int64         `mapstructure:"maxImageSize"`
	ScanConcurrency int           `mapstructure:"scanConcurrency"`
	ScanTimeout     time.Duration `mapstructure:"scanTimeout"`
	Storage         bool          `mapstructure:"storage"`
	VexGeneration   bool          `mapstructure:"vexGeneration"`
}

// LoadConfig reads configuration from file or environment variables.
func LoadConfig(path string) (Config, error) {
	viper.AddConfigPath(path)
	viper.SetConfigName("clusterData")
	viper.SetConfigType("json")

	viper.SetDefault("listingURL", "https://toolbox-data.anchore.io/grype/databases/listing.json")
	viper.SetDefault("maxImageSize", 512*1024*1024)
	viper.SetDefault("scanConcurrency", 1)
	viper.SetDefault("scanTimeout", 5*time.Minute)
	viper.SetDefault("vexGeneration", false)

	viper.AutomaticEnv()

	err := viper.ReadInConfig()
	if err != nil {
		return Config{}, err
	}

	var config Config
	err = viper.Unmarshal(&config)
	return config, err
}

// LoadConfig reads configuration from file or environment variables.
func LoadBackendServicesConfig(path string) (schema.IBackendServices, error) {
	if path == "" {
		return nil, nil
	}

	fullPath := filepath.Join(path, "services.json")
	services, err := servicediscovery.GetServices(
		v1.NewServiceDiscoveryFileV1(fullPath),
	)

	if err != nil {
		return nil, err
	}
	return services, nil
}
