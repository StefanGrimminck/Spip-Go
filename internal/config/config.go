package config

import (
	"fmt"
	"os"

	"github.com/BurntSushi/toml"
)

// Config represents the application configuration
type Config struct {
	// Name identifies this agent instance (used in logs to distinguish hosts)
	Name    string `toml:"name"`
	IP       string `toml:"ip"`
	Port     uint16 `toml:"port"`
	CertPath string `toml:"cert_path,omitempty"`
	KeyPath  string `toml:"key_path,omitempty"`
	LogFile  string `toml:"log_file,omitempty"`
	// Runtime tuning
	ReadTimeoutSeconds  int `toml:"read_timeout_seconds,omitempty"`
	WriteTimeoutSeconds int `toml:"write_timeout_seconds,omitempty"`
	RateLimitPerSecond  int `toml:"rate_limit_per_second,omitempty"`
	RateLimitBurst      int `toml:"rate_limit_burst,omitempty"`
}

// LoadConfig reads and parses the TOML configuration file
func LoadConfig(path string) (*Config, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config Config
	if err := toml.Unmarshal(content, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	return &config, nil
}

// IsTLSEnabled returns true if both certificate and key paths are configured
func (c *Config) IsTLSEnabled() bool {
	return c.CertPath != "" && c.KeyPath != ""
}

// Validate checks if the configuration is valid
func (c *Config) Validate() error {
	if c.Name == "" {
		return fmt.Errorf("name is required in configuration")
	}
	if c.IP == "" {
		return fmt.Errorf("IP address is required")
	}
	if c.Port == 0 {
		return fmt.Errorf("port is required")
	}
	if (c.CertPath != "" && c.KeyPath == "") || (c.CertPath == "" && c.KeyPath != "") {
		return fmt.Errorf("both cert_path and key_path must be provided for TLS")
	}
	return nil
}
