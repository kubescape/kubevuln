package config

import (
	"time"

	"github.com/spf13/viper"
)

type Config struct {
	AccountID            string        `mapstructure:"accountID"`
	BackendOpenAPI       string        `mapstructure:"backendOpenAPI"`
	ClusterName          string        `mapstructure:"clusterName"`
	EventReceiverRestURL string        `mapstructure:"eventReceiverRestURL"`
	KeepLocal            bool          `mapstructure:"keepLocal"`
	ListingURL           string        `mapstructure:"listingURL"`
	MaxImageSize         int64         `mapstructure:"maxImageSize"`
	ScanConcurrency      int           `mapstructure:"scanConcurrency"`
	ScanTimeout          time.Duration `mapstructure:"scanTimeout"`
	Storage              bool          `mapstructure:"storage"`
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

	viper.AutomaticEnv()

	err := viper.ReadInConfig()
	if err != nil {
		return Config{}, err
	}

	var config Config
	err = viper.Unmarshal(&config)
	return config, err
}
