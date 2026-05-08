// Package metrics defines Prometheus instrumentation for proxy behavior.
//
// Architecture fit:
// - The proxy request path invokes this package to emit request/latency signals.
// - The main process exposes these metrics via an HTTP endpoint.
//
// Key responsibilities:
// - Register counters and histograms.
// - Provide helper for per-request observations.
// - Build a Prometheus scrape handler.
//
// Design decisions:
//   - Metrics are registered via explicit registry injection to keep ownership local
//     and avoid global metric collisions.
package metrics

import (
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Collector stores all metric instruments used by proxy runtime.
type Collector struct {
	RequestsTotal prometheus.Counter
	BlockedTotal  prometheus.Counter
	Latency       prometheus.Histogram
}

// New registers and returns proxy metric collectors on the provided registry.
//
// Inputs:
// - reg: Prometheus registerer where instruments are installed.
//
// Outputs:
// - Collector with initialized counters and histogram.
//
// Side effects:
// - Registers metric descriptors and collectors in registry.
//
// Assumptions:
// - Caller passes a valid registerer for the process.
func New(reg prometheus.Registerer) *Collector {
	return &Collector{
		// Register total request counter to track traffic volume.
		RequestsTotal: promauto.With(reg).NewCounter(prometheus.CounterOpts{
			Name: "ztfp_requests_total",
			Help: "Total number of requests seen by proxy",
		}),
		// Register blocked request counter to track enforcement activity.
		BlockedTotal: promauto.With(reg).NewCounter(prometheus.CounterOpts{
			Name: "ztfp_blocked_requests_total",
			Help: "Total blocked requests",
		}),
		// Register latency histogram to monitor tail latencies and SLOs.
		Latency: promauto.With(reg).NewHistogram(prometheus.HistogramOpts{
			Name:    "ztfp_request_latency_seconds",
			Help:    "Request latency in seconds",
			Buckets: prometheus.DefBuckets,
		}),
	}
}

// Observe records request counters and duration.
//
// Inputs:
// - start: request start time.
// - blocked: whether request was denied.
//
// Outputs:
// - None.
//
// Side effects:
// - Mutates Prometheus metric state.
//
// Assumptions:
// - start is captured near request ingress for meaningful latency.
func (c *Collector) Observe(start time.Time, blocked bool) {
	// Count every request seen by the proxy.
	c.RequestsTotal.Inc()
	if blocked {
		// Count enforcement denials separately for security visibility.
		c.BlockedTotal.Inc()
	}
	// Record full request duration in seconds for histogram analysis.
	c.Latency.Observe(time.Since(start).Seconds())
}

// Handle request coming at /metrics endpoint
func Handler(gatherer prometheus.Gatherer) http.Handler {
	return promhttp.HandlerFor(gatherer, promhttp.HandlerOpts{})
}
