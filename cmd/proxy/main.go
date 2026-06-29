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
	"context"
	"errors"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

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

	// Start policy hot-reload watcher so ConfigMap updates take effect without
	// a pod restart.  The watcher stops when the process receives SIGTERM/SIGINT.
	watchCtx, watchCancel := context.WithCancel(context.Background())
	defer watchCancel()
	if err := pe.Watch(watchCtx); err != nil {
		logger.Warnf("policy watcher unavailable (hot-reload disabled): %v", err)
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
	m := metrics.New(reg)

	// ready flips to true once the proxy listener is up and serving.
	// Kubernetes readiness probes read this flag; traffic is only sent to
	// pods where ready == true, preventing premature routing during startup.
	var ready atomic.Bool

	// Launch go routine (HTTP Server for metrics + health probes)
	go func() {
		mux := http.NewServeMux()
		mux.Handle("/metrics", metrics.Handler(reg))

		// Liveness probe
		// if ZeroTrustForwardProxy is alive, return 200 OK.
		mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
		})

		// Readiness probe: To indicate kubernets the pod is ready to serve traffic
		// return 503(StatusServiceUnavailable) until the proxy
		// listener is up. Once its up atomic is set and return 200
		mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
			if ready.Load() {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("ready"))
				return
			}
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("starting"))
		})

		logger.Info("metrics server starting", "addr", cfg.MetricsAddr)
		if err := http.ListenAndServe(cfg.MetricsAddr, mux); err != nil {
			logger.Error("metrics server failed", "error", err)
		}
	}()

	validator := auth.NewJWTValidator(logger, cfg)

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

	// Bind the TCP port before entering the accept loop so we can signal
	// Kubernetes readiness only after the port is actually open.
	ln, err := srv.Listen()
	if err != nil {
		log.Fatalf("proxy listen: %v", err)
	}

	// Port is bound — readiness probe returns 200 from this point forward.
	// Kubernetes will begin routing traffic to this pod.
	ready.Store(true)
	logger.Info("proxy listening, readiness probe active", "addr", cfg.ListenAddr)

	// Serve in a background goroutine so the main goroutine can block
	// waiting for an OS signal and trigger graceful drain.
	startErr := make(chan error, 1)
	go func() {
		startErr <- srv.Serve(ln)
	}()

	// Block until SIGTERM (Kubernetes pod eviction / rolling update) or SIGINT
	// (Ctrl-C during local development) is received.
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGTERM, syscall.SIGINT)

	select {
	case sig := <-quit:
		logger.Info("signal received, starting graceful shutdown", "signal", sig)
	case err := <-startErr:
		// Server failed before any signal — surface the error.
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("proxy server error: %v", err)
		}
		return
	}

	// Allow up to 30 s for in-flight connections to complete before forcing close.
	// 30 s matches the Kubernetes terminationGracePeriodSeconds recommendation.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Fatalf("proxy shutdown error: %v", err)
	}
	logger.Info("proxy stopped cleanly")
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
