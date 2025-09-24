package config

import (
	"os"

	"go.yaml.in/yaml/v3"
)

type Config struct {
	Server Server `yaml:"server"`
}

type Server struct {
	Port               string   `yaml:"port"`
	Host               string   `yaml:"host"`
	FrontendAssetsPath string   `yaml:"frontend_assets_path"`
	Logging            Logging  `yaml:"logging"`
	CORS               CORS     `yaml:"cors"`
	Database           Database `yaml:"database"`
	Security           Security `yaml:"security"`
	LLM                LLM      `yaml:"llm"`
}

type CORS struct {
	AllowedOrigins   []string `koanf:"allowed_origins"`
	AllowedMethods   []string `koanf:"allowed_methods"`
	AllowedHeaders   []string `koanf:"allowed_headers"`
	AllowCredentials bool     `koanf:"allow_credentials"`
	ExposeHeaders    []string `koanf:"expose_headers"`
	MaxAge           int      `koanf:"max_age"`
}

type Caller string

const (
	Backend  Caller = "backend"
	Frontend Caller = "frontend"
)

type Logging struct {
	Level       string         `yaml:"level"`
	Format      string         `yaml:"format"`
	CallerDepth map[Caller]int `yaml:"caller_depth"`
	Output      string         `yaml:"output"`
}

type Tables string

const (
	TableUsers    = "users"
	TableAnalyses = "analyses"
)

type Database struct {
	DSN map[Tables]string `yaml:"dsn"`
}

type Security struct {
	JWTSecret    string `yaml:"jwt_secret"`
	PasswordSalt string `yaml:"password_salt"`
	TokenExpiry  int    `yaml:"token_expiry_hours"`
}

type LLM struct {
	APIKey string `yaml:"api_key"`
	Model  string `yaml:"model"`
}

func LoadConfig(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	defer f.Close()

	var config Config
	err = yaml.NewDecoder(f).Decode(&config)
	if err != nil {
		return nil, err
	}

	return &config, nil
}
