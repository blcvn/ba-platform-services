package configs

import (
	"encoding/json"
	"os"
	"time"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/spf13/viper"
)

type DatabaseConfig struct {
	URL      string `json:"url"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type RedisConfig struct {
	Addr     string `json:"addr"`
	Password string `json:"password"`
	DB       int    `json:"db"`
}

type Config struct {
	Database DatabaseConfig `json:"database"`
	Redis    RedisConfig    `json:"redis"`

	KongHeaders struct {
		UserIDHeader   string `mapstructure:"user_id_header"`
		TenantIDHeader string `mapstructure:"tenant_id_header"`
		RolesHeader    string `mapstructure:"roles_header"`
	} `mapstructure:"kong_headers"`

	Mtls struct {
		CertPath string `mapstructure:"cert_path"`
		KeyPath  string `mapstructure:"key_path"`
	} `mapstructure:"mtls"`
}

const (
	DEFAULT_SECRET_PATH = "/vault/secrets/config.json"
	SECRET_FILE_KEY     = "SECRET_FILE"
	LoadSecretRetries   = 10
	LoadSecretSleep     = 2 * time.Second
)

func LoadConfig() (*Config, error) {
	cfg := &Config{}

	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("./config")
	viper.AddConfigPath(".")
	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err == nil {
		if err := viper.Unmarshal(cfg); err != nil {
			log.Errorf("failed to unmarshal yaml config: %v", err)
		}
	}

	cfgPath := DEFAULT_SECRET_PATH
	if value := os.Getenv(SECRET_FILE_KEY); value != "" {
		cfgPath = value
	}

	var configFile *os.File
	var err error

	for i := 0; i < LoadSecretRetries; i++ {
		if configFile, err = os.Open(cfgPath); err != nil {
			log.Infof("waiting for config file %s... (%d/%d)", cfgPath, i+1, LoadSecretRetries)
			time.Sleep(LoadSecretSleep)
		} else {
			break
		}
	}

	if configFile != nil {
		defer configFile.Close()
		if err := json.NewDecoder(configFile).Decode(cfg); err != nil {
			log.Errorf("failed to decode config.json: %v", err)
			return nil, err
		}
	} else {
		log.Warnf("failed to open secret config %s: %v. Using env vars or defaults.", cfgPath, err)
	}

	if cfg.Database.URL == "" {
		cfg.Database.URL = os.Getenv("DATABASE_URL")
	}

	return cfg, nil
}
