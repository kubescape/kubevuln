package config

import (
	"time"

	"github.com/spf13/viper"
)

type Config struct {
	AccountID            string        `mapstructure:"ACCOUNT_ID"`
	ClusterName          string        `mapstructure:"CLUSTER_NAME"`
	EventReceiverRestURL string        `mapstructure:"EVENT_RECEIVER_REST_URL"`
	GatewayRestURL       string        `mapstructure:"GATEWAY_REST_URL"`
	ScanConcurrency      int           `mapstructure:"SCAN_CONCURRENCY"`
	ScanTimeout          time.Duration `mapstructure:"SCAN_TIMEOUT"`
}

// LoadConfig reads configuration from file or environment variables.
func LoadConfig(path string) (config Config, err error) {
	viper.AddConfigPath(path)
	viper.SetConfigName("app")
	viper.SetConfigType("env")

	viper.SetDefault("GATEWAY_REST_URL", "https://api.armosec.io/api")
	viper.SetDefault("SCAN_CONCURRENCY", 1)
	viper.SetDefault("SCAN_TIMEOUT", 5*time.Minute)

	viper.AutomaticEnv()

	err = viper.ReadInConfig()
	if err != nil {
		return
	}

	err = viper.Unmarshal(&config)
	return
}
