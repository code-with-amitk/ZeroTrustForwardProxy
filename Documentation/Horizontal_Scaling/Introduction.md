# Pod Scaling — ZeroTrustForwardProxy

---

- [Architecture](#arch)
- [Minimum Kubernetes manifests](#min)
- [Helm chart structure (production)](#helm)
- [Things to be Done for Kubernets](#things)

<a href=arch></a>
## Architecture
- Scaling means running proxy process in multiple pods.
- DLP, TSS, proxy are not broken into seperate services:
 -- if we break DLP, TSS and proxy into 3 separate pods there will be a latency on every request, due to sending requests over kubernets network between pods(~0.5–2 ms). For time being we will be staying with the monolith(proxy+DLP+TSS=1pod) that is one proxy containing DLP, TSS but later we will plan to break into multiple pods.
```
NLB
 ├── Pod 1  [TLS + Policy + DLP]
 ├── Pod 2  [TLS + Policy + DLP]
 └── Pod 3  [TLS + Policy + DLP]
```

---

<a href=min></a>
## Minimum Kubernetes manifests

```
k8s/
├── namespace.yaml          # ztfp namespace
├── secret-ca.yaml          # ca.crt + ca.key (same across all environments)
├── configmap-policy.yaml   # policy.yaml content
├── configmap-config.yaml   # config.yaml (listen_addr, metrics_addr, etc.)
├── configmap-blockpage.yaml# block.html template
├── deployment.yaml         # Deployment with 3 replicas, mounts, probes
├── service.yaml            # type=LoadBalancer (provisions NLB on AWS)
├── hpa.yaml                # HorizontalPodAutoscaler — scale on CPU 70%
└── servicemonitor.yaml     # Prometheus ServiceMonitor for scraping :9090
```

<a href=helm></a>
### Helm chart structure (production)

```
helm/ztfp/
├── Chart.yaml
├── values.yaml             # replicaCount, image.tag, resources, etc.
└── templates/
    ├── deployment.yaml
    ├── service.yaml
    ├── hpa.yaml
    ├── configmap.yaml
    ├── secret.yaml
    └── servicemonitor.yaml
```

Deploy with:

```bash
helm install ztfp ./helm/ztfp \
  --set replicaCount=3 \
  --set image.tag=v1.2.0 \
  --set resources.limits.cpu=4000m \
  --set resources.limits.memory=4Gi
```

---

<a href=things></a>
## Things to be Done for Kubernets
### 1. Graceful SIGTERM shutdown (30 s drain)
- When Kubernetes performs a rolling update(pod1 shutdown, pod2 bringup) or scales down a pod, it sends SIGTERM to the process. Without [SIGTERM](https://code-with-amitk.github.io/Signal_Handling/) the old binary exits immediately, dropping every in-flight connection — browsers see connection resets, HTTPS CONNECT tunnels are torn down mid-stream, and audit events are lost.
- forwardproxy need to:

-- Catches SIGTERM / SIGINT
-- Stops accepting new connections (Shutdown() closes the listener)
-- Waits up to 30 seconds for all active request goroutines to finish naturally
-- Only then exits — matching Kubernetes' default terminationGracePeriodSeconds: 30
-- Zero dropped connections during deploys. This matches Kubernetes' recommended rolling-update pattern.

- Files changed:
```
proxy/server.go — new Listen(), Serve(), Shutdown() methods; httpSrv field added to Server
cmd/proxy/main.go — proxy runs in a goroutine; main blocks on signal, then calls srv.Shutdown(ctx) with a 30 s deadline
```

### 2. /healthz liveness + /readyz readiness probes
- Kubernetes uses two probe types:
- Probe1: Liveness
```
Endpoint: GET /healthz
Meaning: Process is alive
failure Action: Kill pod, restart it
/healthz always returns 200 ok while the process is alive
```
- Probe2: Readiness
```
Endpoint: GET /readyz
Meaning: Pod is ready for traffic
failure Action: Remove from Service endpoints (no traffic sent)
/readyz returns 503 starting during startup, 200 ready once the port is bound
```
- Without these probes Kubernetes has no way to know when a new pod is actually ready. It routes traffic to pods that are still loading the CA or the policy YAML, causing connection failures during startup.
- The ready flag (sync/atomic.Bool) flips to true only after net.Listen() succeeds — the TCP port is bound. This is the correct readiness boundary: the CA is already loaded, policy is loaded, the port is open, and the first connection can be handled

- files Changed
```
proxy/server.go — Listen() binds the port separately so main.go can set ready = true between bind and serve
cmd/proxy/main.go — atomic.Bool flag, two new HandleFunc registrations, bind→ready→serve sequence
```