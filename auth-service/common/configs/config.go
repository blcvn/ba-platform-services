package configs

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

type KongHeadersConfig struct {
	UserIDHeader   string `json:"user_id_header"`
	TenantIDHeader string `json:"tenant_id_header"`
	RolesHeader    string `json:"roles_header"`
}

type RoleConfig struct {
	SuperAdminRole string `json:"super_admin_role"`
}

type Config struct {
	Database  DatabaseConfig `json:"database"`
	Redis     RedisConfig    `json:"redis"`
	JWTSecret string         `json:"jwt_secret"`
}
