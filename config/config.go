// Package config provides runtime configuration loading for the proxy.
//
// Architecture fit:
//   - This package is consumed by the composition root (`cmd/proxy/main.go`) and
//     defines tunable runtime knobs for networking, policy paths, and DLP limits.
//
// Key responsibilities:
// - Define the canonical configuration schema.
// - Provide safe defaults for local and production-like startup.
// - Load and validate YAML configuration files.
//
// Design decisions:
// - Defaults are always applied first, then overridden by YAML.
// - Validation enforces presence of core required values.
package config

import (
	"errors"
	"os"
	"time"
	"zerotrust-forward-proxy/utils"

	"gopkg.in/yaml.v3"
)

type Config struct {
	ListenAddr          string        `yaml:"listen_addr"` //8080
	PolicyFile          string        `yaml:"policy_file"`
	CACertFile          string        `yaml:"ca_cert_file"`
	CAKeyFile           string        `yaml:"ca_key_file"`
	MetricsAddr         string        `yaml:"metrics_addr"`
	IdleConnTimeout     time.Duration `yaml:"idle_conn_timeout"`
	MaxIdleConns        int           `yaml:"max_idle_conns"`
	MaxIdleConnsPerHost int           `yaml:"max_idle_conns_per_host"`
	RequestTimeout      time.Duration `yaml:"request_timeout"`
	MaxInspectBodyBytes int64         `yaml:"max_inspect_body_bytes"`
}

// Default returns baseline runtime settings used when fields are omitted.
//
// Inputs:
// - None.
//
// Outputs:
// - A fully populated Config with safe defaults.
//
// Side effects:
// - None.
//
// Assumptions:
// - Caller may override any field via YAML after this baseline.
func Default() Config {
	return Config{
		ListenAddr:          ":8080",
		PolicyFile:          "policy.yaml",
		CACertFile:          "ca.crt",
		CAKeyFile:           "ca.key",
		MetricsAddr:         ":9090",
		IdleConnTimeout:     90 * time.Second,
		MaxIdleConns:        512,
		MaxIdleConnsPerHost: 128,
		RequestTimeout:      30 * time.Second,
		MaxInspectBodyBytes: 1 << 20,
	}
}

// Read config file & return variable cfg=Config struct
func Load(path string) (Config, error) {
	utils.GetFunctionName()

	// Initialize cfg with default values
	cfg := Default()
	if path == "" {
		return cfg, nil
	}

	// Read file contents as bytes
	b, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}

	// Write the bytes read(b) into cfg variable.
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return cfg, err
	}

	// Mandatory fields cannot be empty
	if cfg.ListenAddr == "" || cfg.PolicyFile == "" || cfg.CACertFile == "" || cfg.CAKeyFile == "" || cfg.MetricsAddr == "" {
		return cfg, errors.New("config has required empty fields")
	}

	// Restore inspection safety limit if invalid value was supplied.
	if cfg.MaxInspectBodyBytes <= 0 {
		cfg.MaxInspectBodyBytes = Default().MaxInspectBodyBytes
	}
	return cfg, nil
}
