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
	AppConfig     *Config
	KongHeaderCfg *KongHeadersConfig
	RoleCfg       *RoleConfig
	config        *viper.Viper

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

	// Load Kong Headers configuration from YAML config with environment variable fallbacks
	KongHeaderCfg = &KongHeadersConfig{}
	KongHeaderCfg.UserIDHeader = config.GetString("kong_headers.user_id_header")
	if KongHeaderCfg.UserIDHeader == "" {
		KongHeaderCfg.UserIDHeader = os.Getenv("KONG_HEADER_USER_ID")
		if KongHeaderCfg.UserIDHeader == "" {
			KongHeaderCfg.UserIDHeader = DEFAULT_KONG_HEADER_USER_ID // Default value
		}
	}

	KongHeaderCfg.TenantIDHeader = config.GetString("kong_headers.tenant_id_header")
	if KongHeaderCfg.TenantIDHeader == "" {
		KongHeaderCfg.TenantIDHeader = os.Getenv("KONG_HEADER_TENANT_ID")
		if KongHeaderCfg.TenantIDHeader == "" {
			KongHeaderCfg.TenantIDHeader = DEFAULT_KONG_HEADER_TENANT_ID // Default value
		}
	}

	KongHeaderCfg.RolesHeader = config.GetString("kong_headers.roles_header")
	if KongHeaderCfg.RolesHeader == "" {
		KongHeaderCfg.RolesHeader = os.Getenv("KONG_HEADER_ROLES")
		if KongHeaderCfg.RolesHeader == "" {
			KongHeaderCfg.RolesHeader = DEFAULT_KONG_HEADER_ROLES // Default value
		}
	}

	// Load Role configuration from YAML config with environment variable fallbacks
	RoleCfg = &RoleConfig{}
	RoleCfg.SuperAdminRole = config.GetString("roles.super_admin_role")
	if RoleCfg.SuperAdminRole == "" {
		RoleCfg.SuperAdminRole = os.Getenv("SUPER_ADMIN_ROLE")
		if RoleCfg.SuperAdminRole == "" {
			RoleCfg.SuperAdminRole = DEFAULT_SUPER_ADMIN_ROLE // Default value
		}
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
	if cfg.Redis.Addr == "" {
		cfg.Redis.Addr = os.Getenv("REDIS_ADDR")
		if cfg.Redis.Addr == "" {
			appLog.Fatalf("REDIS_ADDR is not set")
		}
	}
	if cfg.JWTSecret == "" {
		cfg.JWTSecret = os.Getenv("JWT_SECRET")
		if cfg.JWTSecret == "" {
			appLog.Fatalf("JWT_SECRET is not set")
		}
	}

	// Set global config for hash utilities
	AppConfig = &cfg
}
