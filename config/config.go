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
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
	"zerotrust-forward-proxy/utils"

	"gopkg.in/yaml.v3"
)

type Config struct {
	ListenAddr          string        `yaml:"listen_addr"` //8080
	PolicyFile          string        `yaml:"policy_file"`
	PolicyDir           string        `yaml:"policy_dir"`
	TenantMode          string        `yaml:"tenant_mode"`
	DefaultTenant       string        `yaml:"default_tenant"`
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
		PolicyDir:           "/var/ztfp/policies/",
		TenantMode:          "dev",
		DefaultTenant:       "default",
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
		return finalizeConfig(cfg)
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

	return finalizeConfig(cfg)
}

func finalizeConfig(cfg Config) (Config, error) {
	if cfg.PolicyDir == "" {
		cfg.PolicyDir = Default().PolicyDir
	}
	if cfg.TenantMode == "" {
		cfg.TenantMode = Default().TenantMode
	}
	if cfg.DefaultTenant == "" {
		cfg.DefaultTenant = Default().DefaultTenant
	}
	cfg.TenantMode = normalizeTenantMode(cfg.TenantMode)

	if err := applyEnvOverrides(&cfg); err != nil {
		return cfg, fmt.Errorf("env override: %w", err)
	}
	return cfg, nil
}

// applyEnvOverrides reads ZTFP_* environment variables and writes any
// non-empty values over the corresponding config fields.  Env vars are
// applied last so they always win over YAML file contents.
//
// Supported variables (all optional):
//
//	ZTFP_LISTEN_ADDR            string  e.g. ":8080"
//	ZTFP_POLICY_FILE            string  path to policy.yaml
//	ZTFP_CA_CERT_FILE           string  path to ca.crt
//	ZTFP_CA_KEY_FILE            string  path to ca.key
//	ZTFP_METRICS_ADDR           string  e.g. ":9090"
//	ZTFP_IDLE_CONN_TIMEOUT      duration e.g. "90s"
//	ZTFP_MAX_IDLE_CONNS         int
//	ZTFP_MAX_IDLE_CONNS_PER_HOST int
//	ZTFP_REQUEST_TIMEOUT        duration e.g. "30s"
//	ZTFP_MAX_INSPECT_BODY_BYTES int64
//	ZTFP_POLICY_DIR             string  root dir for per-tenant policy.db trees
//	ZTFP_TENANT_MODE            string  "strict" or "dev"
//	ZTFP_DEFAULT_TENANT         string  fallback tenant_id when mode=dev and claim absent
func applyEnvOverrides(cfg *Config) error {
	if v := os.Getenv("ZTFP_LISTEN_ADDR"); v != "" {
		cfg.ListenAddr = v
	}
	if v := os.Getenv("ZTFP_POLICY_FILE"); v != "" {
		cfg.PolicyFile = v
	}
	if v := os.Getenv("ZTFP_POLICY_DIR"); v != "" {
		cfg.PolicyDir = v
	}
	if v := os.Getenv("ZTFP_TENANT_MODE"); v != "" {
		cfg.TenantMode = normalizeTenantMode(v)
	}
	if v := os.Getenv("ZTFP_DEFAULT_TENANT"); v != "" {
		cfg.DefaultTenant = v
	}
	if v := os.Getenv("ZTFP_CA_CERT_FILE"); v != "" {
		cfg.CACertFile = v
	}
	if v := os.Getenv("ZTFP_CA_KEY_FILE"); v != "" {
		cfg.CAKeyFile = v
	}
	if v := os.Getenv("ZTFP_METRICS_ADDR"); v != "" {
		cfg.MetricsAddr = v
	}
	if v := os.Getenv("ZTFP_IDLE_CONN_TIMEOUT"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return fmt.Errorf("ZTFP_IDLE_CONN_TIMEOUT: %w", err)
		}
		cfg.IdleConnTimeout = d
	}
	if v := os.Getenv("ZTFP_MAX_IDLE_CONNS"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return fmt.Errorf("ZTFP_MAX_IDLE_CONNS: %w", err)
		}
		cfg.MaxIdleConns = n
	}
	if v := os.Getenv("ZTFP_MAX_IDLE_CONNS_PER_HOST"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return fmt.Errorf("ZTFP_MAX_IDLE_CONNS_PER_HOST: %w", err)
		}
		cfg.MaxIdleConnsPerHost = n
	}
	if v := os.Getenv("ZTFP_REQUEST_TIMEOUT"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return fmt.Errorf("ZTFP_REQUEST_TIMEOUT: %w", err)
		}
		cfg.RequestTimeout = d
	}
	if v := os.Getenv("ZTFP_MAX_INSPECT_BODY_BYTES"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return fmt.Errorf("ZTFP_MAX_INSPECT_BODY_BYTES: %w", err)
		}
		cfg.MaxInspectBodyBytes = n
	}
	return nil
}

func normalizeTenantMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "strict":
		return "strict"
	default:
		return "dev"
	}
}
