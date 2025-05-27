package config

import (
	"fmt"
	"os"

	"github.com/BurntSushi/toml"
)

// Config represents the application configuration
type Config struct {
	IP       string `toml:"ip"`
	Port     uint16 `toml:"port"`
	CertPath string `toml:"cert_path,omitempty"`
	KeyPath  string `toml:"key_path,omitempty"`
	LogFile  string `toml:"log_file,omitempty"`
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
