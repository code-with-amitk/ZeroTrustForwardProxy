**Prometheus**
- [What is Prometheus](#what)
- [Register metrics](#register)
- [Increment metrics](#increment)
- [Send metrics on /metrics (9090)](#send)
- [Get metrics using curl](#get)


<a href=what></a>
## Promethus

- [Prometheus](https://github.com/code-with-amitk/Code-examples/tree/master/System-Design/Concepts/Logging_and_Monitoring/Prometheus) is a widely used, open-source systems monitoring and alerting toolkit designed for containerized and microservices-based environments like Kubernetes

<a  href=register></a>
### Register metrics
- [metrics](https://github.com/code-with-amitk/Code-examples/blob/master/System-Design/Concepts/Logging_and_Monitoring/Prometheus/README.md#2-metrics) can be registered using promauto package
```
// register counter
RequestsTotal: promauto.With(reg).NewCounterVec(prometheus.CounterOpts{
			Name: "ztfp_requests_total",
			Help: "Total requests by user, domain and action (allow|block)",
		}, []string{"user", "domain", "action"}),

// register histogram
Latency: promauto.With(reg).NewHistogram(prometheus.HistogramOpts{
			Name:    "ztfp_request_latency_seconds",
			Help:    "Request latency in seconds",
			Buckets: prometheus.DefBuckets,
		}),
```

<a  href=increment></a>
### Increment metrics
```
// Labeled counter for per-user/domain/action HPA signals.
c.RequestsTotal.With(prometheus.Labels{
    "user":   user,
    "domain": domain,
    "action": action,
}).Inc()
```

<a  href=send></a>
### Send metrics on /metrics (9090)
```
main()	//cmd/proxy/main.go
	reg := prometheus.NewRegistry()
	m := metrics.New(reg)
	// go routine (metrics + health probes)
	go func() {
		mux.Handle("/metrics", metrics.Handler(reg))
		http.ListenAndServe(cfg.MetricsAddr(9090), mux)
	}
```

<a href=get></a>
### Get metrics using curl
```json
$ curl -X GET http://127.0.0.1:9090/metrics -H "Content-Type: application/json"
# HELP ztfp_blocked_requests_total Total blocked requests
# TYPE ztfp_blocked_requests_total counter
ztfp_blocked_requests_total 1
# HELP ztfp_dlp_violations_total Total DLP violations detected
# TYPE ztfp_dlp_violations_total counter
ztfp_dlp_violations_total 1
# HELP ztfp_mitm_cert_cache_hits_total Total MITM certificate cache hits
# TYPE ztfp_mitm_cert_cache_hits_total counter
ztfp_mitm_cert_cache_hits_total 0
# HELP ztfp_mitm_cert_cache_misses_total Total MITM certificate cache misses
# TYPE ztfp_mitm_cert_cache_misses_total counter
ztfp_mitm_cert_cache_misses_total 3
# HELP ztfp_request_bytes_inspected_total Total request body bytes inspected
# TYPE ztfp_request_bytes_inspected_total counter
ztfp_request_bytes_inspected_total 29
# HELP ztfp_request_latency_seconds Request latency in seconds
# TYPE ztfp_request_latency_seconds histogram
ztfp_request_latency_seconds_bucket{le="0.005"} 0
ztfp_request_latency_seconds_bucket{le="0.01"} 2
ztfp_request_latency_seconds_bucket{le="0.025"} 2
ztfp_request_latency_seconds_bucket{le="0.05"} 2
ztfp_request_latency_seconds_bucket{le="0.1"} 2
ztfp_request_latency_seconds_bucket{le="0.25"} 2
ztfp_request_latency_seconds_bucket{le="0.5"} 3
ztfp_request_latency_seconds_bucket{le="1"} 4
ztfp_request_latency_seconds_bucket{le="2.5"} 4
ztfp_request_latency_seconds_bucket{le="5"} 4
ztfp_request_latency_seconds_bucket{le="10"} 4
ztfp_request_latency_seconds_bucket{le="+Inf"} 4
ztfp_request_latency_seconds_sum 1.040651709
ztfp_request_latency_seconds_count 4
# HELP ztfp_requests_total Total requests by user, domain and action (allow|block)
# TYPE ztfp_requests_total counter
ztfp_requests_total{action="allow",domain="example.com",user="alice"} 1
ztfp_requests_total{action="allow",domain="google.com",user="alice"} 1
ztfp_requests_total{action="allow",domain="www.google.com",user="alice"} 1
ztfp_requests_total{action="block",domain="example.com",user="alice"} 1
# HELP ztfp_response_bytes_inspected_total Total response body bytes inspected
# TYPE ztfp_response_bytes_inspected_total counter
ztfp_response_bytes_inspected_total 28185
# HELP ztfp_tls_handshake_seconds TLS handshake latency in seconds
# TYPE ztfp_tls_handshake_seconds histogram
ztfp_tls_handshake_seconds_bucket{le="0.005"} 0
ztfp_tls_handshake_seconds_bucket{le="0.01"} 0
ztfp_tls_handshake_seconds_bucket{le="0.025"} 0
ztfp_tls_handshake_seconds_bucket{le="0.05"} 0
ztfp_tls_handshake_seconds_bucket{le="0.1"} 0
ztfp_tls_handshake_seconds_bucket{le="0.25"} 0
ztfp_tls_handshake_seconds_bucket{le="0.5"} 0
ztfp_tls_handshake_seconds_bucket{le="1"} 0
ztfp_tls_handshake_seconds_bucket{le="2.5"} 0
ztfp_tls_handshake_seconds_bucket{le="5"} 0
ztfp_tls_handshake_seconds_bucket{le="10"} 0
ztfp_tls_handshake_seconds_bucket{le="+Inf"} 0
ztfp_tls_handshake_seconds_sum 0
ztfp_tls_handshake_seconds_count 0
```
