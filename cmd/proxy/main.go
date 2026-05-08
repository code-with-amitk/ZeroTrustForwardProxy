// Package main bootstraps the Zero Trust Forward Proxy runtime.
//
// Architecture fit:
//   - This file is the composition root for the entire system.
//   - It wires together configuration, policy, certificate authority, DLP inspector,
//     metrics collector, and proxy server implementation.
//
// Key responsibilities:
// - Parse startup flags and load YAML config.
// - Initialize infrastructure dependencies in a deterministic order.
// - Start the metrics endpoint and main proxy listener.
//
// Design decisions:
//   - Dependency wiring is explicit (no hidden globals or DI framework).
//   - Logging is structured JSON from process start.
//   - Metrics server runs in a dedicated goroutine to isolate telemetry serving
//     from proxy request path.
package main

import (
	"flag"
	"log"
	"net/http"
	"strings"

	"github.com/prometheus/client_golang/prometheus"

	"zerotrust-forward-proxy/auth"
	"zerotrust-forward-proxy/config"
	"zerotrust-forward-proxy/inspector"
	"zerotrust-forward-proxy/logging"
	"zerotrust-forward-proxy/metrics"
	"zerotrust-forward-proxy/policy"
	"zerotrust-forward-proxy/proxy"
	"zerotrust-forward-proxy/utils"
)

// Start metrics(9009), proxy HTTP(8080) servers
func main() {
	utils.GetFunctionName()

	logger, err := logging.InitLogger()
	if err != nil {
		logger.Error(err)
	}
	logger.Debug("Logger initialized successfully")

	// Declare variable=config which store file name only
	configPath := flag.String("config", "config.yaml", "Path to YAML configuration")
	flag.Parse()

	// Read file into cfg struct
	cfg, err := config.Load(*configPath)
	if err != nil {
		logger.Error("load config: %v", err)
	}

	// Read config.yaml into Config struct
	pe, err := policy.Load(logger, cfg.PolicyFile)
	if err != nil {
		logger.Error("load policy: %v", err)
	}

	// openssl x509 -in ca.crt -text -noout
	// Issuer: O = ZeroTrustForwardProxy, CN = ZeroTrust Forward Proxy Root CA
	// Subject: O = ZeroTrustForwardProxy, CN = ZeroTrust Forward Proxy Root CA
	ca, err := proxy.LoadOrCreateCA(cfg.CACertFile, cfg.CAKeyFile)
	if err != nil {
		logger.Fatalf("load/create CA: %v", err)
	}

	// Create promethemus registry
	reg := prometheus.NewRegistry()
	// Register all proxy metric collectors against the process registry.
	m := metrics.New(reg)

	// Launch go routine (HTTP Server for metrics)
	go func() {

		// REST endpoints using mux
		mux := http.NewServeMux()
		mux.Handle("/metrics", metrics.Handler(reg))
		logger.Info("metrics server starting", "addr", cfg.MetricsAddr)

		// Start HTTP Server
		if err := http.ListenAndServe(cfg.MetricsAddr, mux); err != nil {
			logger.Error("metrics server failed", "error", err)
		}
	}()

	validator := auth.NewMockJWTValidator(logger)

	// pointer to proxy server struct
	srv := proxy.New(
		cfg,
		ca,
		validator,
		pe,
		// Create payload inspector with configured max body bytes to bound memory usage.
		inspector.New(cfg.MaxInspectBodyBytes),
		m,
		logger,
	)

	logger.Info("proxy starting addr: ", cfg.ListenAddr)

	// main block on proxy server
	if err := srv.Start(); err != nil {
		log.Fatal(err)
	}
}

// shortFuncName returns compact function signature for logs.
func shortFuncName(full string) string {
	full = strings.TrimSpace(full)
	if full == "" {
		return "unknown()"
	}
	lastSlash := strings.LastIndex(full, "/")
	if lastSlash >= 0 && lastSlash+1 < len(full) {
		full = full[lastSlash+1:]
	}
	parts := strings.Split(full, ".")
	if len(parts) >= 2 {
		name := parts[len(parts)-1]
		if strings.HasPrefix(name, "(") && len(parts) >= 3 {
			name = parts[len(parts)-2]
		}
		if strings.HasSuffix(name, ")") {
			return name
		}
		return name + "()"
	}
	if strings.HasSuffix(full, ")") {
		return full
	}
	return full + "()"
}
