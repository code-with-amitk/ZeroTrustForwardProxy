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
	RequestsTotal          prometheus.Counter
	BlockedTotal           prometheus.Counter
	Latency                prometheus.Histogram
	HandshakeLatency       prometheus.Histogram
	CertCacheHits          prometheus.Counter
	CertCacheMisses        prometheus.Counter
	DLPViolationsTotal     prometheus.Counter
	RequestBytesInspected  prometheus.Counter
	ResponseBytesInspected prometheus.Counter
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
		HandshakeLatency: promauto.With(reg).NewHistogram(prometheus.HistogramOpts{
			Name:    "ztfp_tls_handshake_seconds",
			Help:    "TLS handshake latency in seconds",
			Buckets: prometheus.DefBuckets,
		}),
		CertCacheHits: promauto.With(reg).NewCounter(prometheus.CounterOpts{
			Name: "ztfp_mitm_cert_cache_hits_total",
			Help: "Total MITM certificate cache hits",
		}),
		CertCacheMisses: promauto.With(reg).NewCounter(prometheus.CounterOpts{
			Name: "ztfp_mitm_cert_cache_misses_total",
			Help: "Total MITM certificate cache misses",
		}),
		DLPViolationsTotal: promauto.With(reg).NewCounter(prometheus.CounterOpts{
			Name: "ztfp_dlp_violations_total",
			Help: "Total DLP violations detected",
		}),
		RequestBytesInspected: promauto.With(reg).NewCounter(prometheus.CounterOpts{
			Name: "ztfp_request_bytes_inspected_total",
			Help: "Total request body bytes inspected",
		}),
		ResponseBytesInspected: promauto.With(reg).NewCounter(prometheus.CounterOpts{
			Name: "ztfp_response_bytes_inspected_total",
			Help: "Total response body bytes inspected",
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

func (c *Collector) ObserveHandshake(start time.Time) {
	c.HandshakeLatency.Observe(time.Since(start).Seconds())
}

func (c *Collector) RecordCertCacheHit() {
	c.CertCacheHits.Inc()
}

func (c *Collector) RecordCertCacheMiss() {
	c.CertCacheMisses.Inc()
}

func (c *Collector) RecordDLPViolation() {
	c.DLPViolationsTotal.Inc()
}

func (c *Collector) RecordRequestBytesInspected(n int64) {
	if n > 0 {
		c.RequestBytesInspected.Add(float64(n))
	}
}

func (c *Collector) RecordResponseBytesInspected(n int64) {
	if n > 0 {
		c.ResponseBytesInspected.Add(float64(n))
	}
}

// Handle request coming at /metrics endpoint
func Handler(gatherer prometheus.Gatherer) http.Handler {
	return promhttp.HandlerFor(gatherer, promhttp.HandlerOpts{})
}
