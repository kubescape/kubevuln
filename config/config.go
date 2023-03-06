package config

import "github.com/spf13/viper"

type Config struct {
	AccountID        string `mapstructure:"ACCOUNT_ID"`
	ClusterName      string `mapstructure:"CLUSTER_NAME"`
	EventReceiverURL string `mapstructure:"EVENT_RECEIVER_URL"`
	ScanConcurrency  int    `mapstructure:"SCAN_CONCURRENCY"`
}

// LoadConfig reads configuration from file or environment variables.
func LoadConfig(path string) (config Config, err error) {
	viper.AddConfigPath(path)
	viper.SetConfigName("app")
	viper.SetConfigType("env")

	viper.AutomaticEnv()

	err = viper.ReadInConfig()
	if err != nil {
		return
	}

	err = viper.Unmarshal(&config)
	return
}
