# Concurrency and Goroutine Model

## Goroutines Used

```mermaid
flowchart TD
    M[main goroutine] --> P[proxy ListenAndServe]
    M --> MS[metrics ListenAndServe]
    P -->|per incoming connection| G1[connection goroutine]
    G1 -->|CONNECT MITM| G2[request loop over TLS tunnel]
```

- 1 goroutine for main control path.
- 1 dedicated goroutine for metrics endpoint server.
- `net/http` spawns goroutines per connection/request automatically.
- CONNECT MITM handling stays non-blocking across clients because each tunnel runs independently.

## Why This Works
- Goroutine-per-connection is suitable for high concurrency in Go.
- Shared resources are concurrency-safe:
  - CA cert cache guarded by RWMutex
  - HTTP transport uses internal pooling and safe reuse
- No global blocking calls in hot path besides network I/O.
