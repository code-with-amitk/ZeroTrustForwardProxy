- [1. Graceful SIGTERM shutdown (30 s drain)](#graceful)
- [2. /healthz liveness + /readyz readiness probes](#healthz)


## Things to be Done for Kubernets

<a href=graceful></a>
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

<a href=healthz></a>
### 2. /healthz liveness + /readyz readiness probes
- Kubernetes uses two probe types:
- Probe1: Liveness
```c
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
```c
proxy/server.go — Listen() binds the port separately so main.go can set ready = true between bind and serve
cmd/proxy/main.go — atomic.Bool flag, two new HandleFunc registrations, bind→ready→serve sequence
```