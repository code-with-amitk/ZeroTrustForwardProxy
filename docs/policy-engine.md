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
    A[HTTP or CONNECT request enters proxy handler] --> B[Function call evaluate];

    subgraph EV[evaluate in proxy/server.go]
        B --> C[Auth.ExtractAuthorizationnHeader];
        C --> D{Auth extraction error?};
        D -- No --> E[Set user = id.User];
        D -- Yes --> F[Keep user empty and continue];
        E --> G[domain = targetDomain];
        F --> G;

        G --> H[targetDomain: if URL.Host exists use stripPort, else stripPort];

        H --> I[Policy.Decide function];
        I --> J{Decision is Block?};
        J -- Yes --> K[Return blocked=true, status=403, reason=policy blocked request];
        J -- No --> L[Inspector.InspectRequest function];

        L --> M{Inspection error?};
        M -- Yes --> N[Return blocked=true, status=400, reason=inspection failed];
        M -- No --> O{Any violations? voliation_length > 0};
        O -- Yes --> P[Return blocked=true, status=403, reason=dlp violation, viol set];
        O -- No --> Q[Return blocked=false, status=0, reason empty];
    end

    subgraph HTTPPATH[Caller behavior in handleHTTP]
        K --> R[Blocked path];
        N --> R;
        P --> R;
        R --> S[Respond 403 with coaching HTML block page];
        S --> T[Audit: action=blocked with reason and violations];

        Q --> U[Allowed path];
        U --> V[Clone and normalize outbound request];
        V --> W[Transport.RoundTrip];
        W --> X{RoundTrip error?};
        X -- Yes --> Y[Respond 502 Bad Gateway and audit blocked];
        X -- No --> Z[Copy upstream headers and body, mirror status];
        Z --> AA[Audit: action=allowed];
    end

    subgraph CONNECTPATH[Caller behavior in handleConnect]
        K --> AB[Deny CONNECT early];
        N --> AB;
        P --> AB;
        AB --> AC[Respond 403 and audit blocked];

        Q --> AD[Proceed with TLS MITM tunnel setup];
        AD --> AE[Per tunneled request, request and response DLP checks run around RoundTrip];
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
