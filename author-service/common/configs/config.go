package configs

type DatabaseConfig struct {
	URL      string `json:"url"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type Config struct {
	Database DatabaseConfig `json:"database"`
}
