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
	ScanConcurrency      int           `mapstructure:"scanConcurrency"`
	ScanTimeout          time.Duration `mapstructure:"scanTimeout"`
}

// LoadConfig reads configuration from file or environment variables.
func LoadConfig(path string) (config Config, err error) {
	viper.AddConfigPath(path)
	viper.SetConfigName("clusterData")
	viper.SetConfigType("json")

	viper.SetDefault("scanConcurrency", 1)
	viper.SetDefault("scanTimeout", 5*time.Minute)

	viper.AutomaticEnv()

	err = viper.ReadInConfig()
	if err != nil {
		return
	}

	err = viper.Unmarshal(&config)
	return
}
