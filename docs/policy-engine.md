# Policy Engine
## Policy format (policy.yaml)
* Policy is set of rules which contains domain, user, action
* ie for particular domain, user. What would be the action
* Policies are evaluated from top to bottom and checked for match

## Flow
* policy.yaml is read into internal DS
```
rules:
  - user: "alice"
    domain: "www.google.com"
    action: allow
```

* Whenever a request arrives at proxy handlers (`handleHTTP` / `handleConnect`), both paths call:
  * `func (s *Server) evaluate(r *http.Request) (user, domain string, blocked bool, status int, reason string, viol []inspector.Violation)`

### In-depth evaluate() decision flow
```mermaid
flowchart TD
    A[HTTP or CONNECT request enters proxy handler] --> B[Call evaluate(r)]

    subgraph EV [evaluate(r) in proxy/server.go]
        B --> C[Auth.ExtractAuthorizationnHeader(r)]
        C --> D{Auth extraction error?}
        D -- No --> E[Set user = id.User]
        D -- Yes --> F[Keep user empty and continue]
        E --> G[domain = targetDomain(r)]
        F --> G

        G --> H[targetDomain logic:
        if r.URL.Host exists use stripPort(r.URL.Host)
        else use stripPort(r.Host)]

        H --> I[Policy.Decide(user, domain)]
        I --> J{Decision == Block?}
        J -- Yes --> K[Return:
        user, domain, blocked=true,
        status=403, reason=policy blocked request, viol=nil]
        J -- No --> L[Inspector.InspectRequest(r)]

        L --> M{Inspection error?}
        M -- Yes --> N[Return:
        user, domain, blocked=true,
        status=400, reason=inspection failed, viol=nil]
        M -- No --> O{len(viol) > 0 ?}
        O -- Yes --> P[Return:
        user, domain, blocked=true,
        status=403, reason=dlp violation, viol=detected items]
        O -- No --> Q[Return:
        user, domain, blocked=false,
        status=0, reason=empty, viol=nil]
    end

    subgraph HTTPPATH [Caller behavior in handleHTTP]
        K --> R[blocked path]
        N --> R
        P --> R
        R --> S[Respond 403 with rendered coaching HTML block page]
        S --> T[Audit log action=blocked with reason/violations]

        Q --> U[allowed path]
        U --> V[Clone + normalize outbound request]
        V --> W[Transport.RoundTrip(outReq)]
        W --> X{RoundTrip error?}
        X -- Yes --> Y[Respond 502 Bad Gateway + audit blocked]
        X -- No --> Z[Copy upstream headers/body + status]
        Z --> AA[Audit log action=allowed]
    end

    subgraph CONNECTPATH [Caller behavior in handleConnect]
        K --> AB[deny CONNECT early]
        N --> AB
        P --> AB
        AB --> AC[Respond 403 + audit blocked]

        Q --> AD[Proceed with TLS MITM tunnel setup]
        AD --> AE[Per tunneled request:
        request/response DLP checks still run before/after RoundTrip]
    end
```

### Action=Allow
* On action=Allow, request is forwarded to destination server
* As response is received from destination server, response is returned to client

### Action=Block
* Request is dropped at proxy and a coaching message is sent to client (HTTP path) or denied for CONNECT

## Evaluation Logic
- Rule matching is first-match-wins.
- `user` can be exact or `*`.
- `domain` supports:
  - exact: `example.com`
  - wildcard suffix: `*.example.com`
  - global wildcard: `*`
- If no rule matches, `default_action` is used.
