package config

import (
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

// Config holds application configuration
type Config struct {
	DataDir       string        `yaml:"data_dir"`
	CollectInterval time.Duration `yaml:"collect_interval"`
	RetentionDays int           `yaml:"retention_days"`
	HTTPPort      int           `yaml:"http_port"`
	EnableHTTP    bool          `yaml:"enable_http"`
	LogLevel      string        `yaml:"log_level"`
}

// DefaultConfig returns the default configuration
func DefaultConfig() *Config {
	homeDir, _ := os.UserHomeDir()
	return &Config{
		DataDir:         filepath.Join(homeDir, ".config", "sectimeline", "data"),
		CollectInterval: 5 * time.Minute,
		RetentionDays:   90,
		HTTPPort:        9012,
		EnableHTTP:      true,
		LogLevel:        "info",
	}
}

// LoadConfig loads configuration from a file
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	config := DefaultConfig()
	if err := yaml.Unmarshal(data, config); err != nil {
		return nil, err
	}

	return config, nil
}

// SaveConfig saves configuration to a file
func SaveConfig(config *Config, path string) error {
	data, err := yaml.Marshal(config)
	if err != nil {
		return err
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	return os.WriteFile(path, data, 0644)
}

// ConfigPath returns the default config file path
func ConfigPath() string {
	homeDir, _ := os.UserHomeDir()
	return filepath.Join(homeDir, ".config", "sectimeline", "config.yaml")
}

// EnsureConfigDir ensures the config directory exists
func EnsureConfigDir() error {
	homeDir, _ := os.UserHomeDir()
	configDir := filepath.Join(homeDir, ".config", "sectimeline")
	return os.MkdirAll(configDir, 0755)
}
