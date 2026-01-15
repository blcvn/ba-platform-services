package configs

import (
	"encoding/json"
	"os"
	"path"
	"time"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/spf13/viper"
)

var (
	AppConfig *Config
	config    *viper.Viper

	//mTLS file
	TLSCertPath string = "/vault/secrets/bundle.pem"
	TLSKeyPath  string = "/vault/secrets/bundle.pem"

	LoadSecretRetries = 10
	LoadSecretSleep   = 2 * time.Second
)

func Init(applog *log.Helper) {
	AppConfig = &Config{}
	loadEnvironment(applog)
	loadSercet(applog)
}

func loadEnvironment(appLog *log.Helper) {
	file := DEFAULT_CONFIG_FILE
	if value := os.Getenv(CONFIG_FILE_KEY); value != "" {
		file = value
	}
	config = viper.New()
	config.SetConfigType("yaml")
	fileName := path.Base(file)
	config.SetConfigName(fileName)
	folder := path.Dir(file)
	config.AddConfigPath(folder)
	config.AddConfigPath("./config/")
	config.AddConfigPath("../config/")
	err := config.ReadInConfig()
	if err != nil {
		appLog.Fatalf("error on parsing configuration file: %s", err.Error())
	}

	// Load mTLS configuration from YAML config with environment variable fallbacks
	if value := config.GetString("mtls.cert_path"); value != "" {
		TLSCertPath = value
	}
	if value := config.GetString("mtls.key_path"); value != "" {
		TLSKeyPath = value
	}
}

func loadSercet(appLog *log.Helper) {
	// 1. Load Config from Vault Agent secrets (with retry)
	cfgPath := DEFAULT_SECRET_PATH
	if value := os.Getenv(SECRET_FILE_KEY); value != "" {
		cfgPath = value
	}
	var configFile *os.File
	var err error

	for i := 0; i < LoadSecretRetries; i++ {
		if configFile, err = os.Open(cfgPath); err != nil {
			appLog.Infof("waiting for config file %s... (%d/%d)", cfgPath, i+1, LoadSecretRetries)
			time.Sleep(LoadSecretSleep)
		} else {
			break
		}
	}

	if configFile == nil {
		appLog.Fatalf("failed to open config: %v. falling back to env.", err)
	}

	var cfg Config
	if err := json.NewDecoder(configFile).Decode(&cfg); err != nil {
		appLog.Fatalf("failed to decode config: %v", err)
	}
	configFile.Close()
	if cfg.Database.URL == "" {
		cfg.Database.URL = os.Getenv("DATABASE_URL")
		if cfg.Database.URL == "" {
			appLog.Fatalf("DATABASE_URL is not set")
		}
	}

	// Set global config
	AppConfig = &cfg
}
