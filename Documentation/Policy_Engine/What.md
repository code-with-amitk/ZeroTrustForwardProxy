- [Policy format](#pf)
- [Flow](#flow)
- [Policy Structure](#ps)

# Policy Engine

<a name=pf></a>
## Policy format (sqlite3 db file)
* Policy is set of rules which contains domain, user, action
* ie for particular domain, user. What would be the action
* Policies are evaluated from top to bottom and checked for match

<a name=flow></a>
## Flow
- Policy processing is done in 2 paths. There are 2 seperate services controlplane(policy preprocessing), dataplane(go). Both containers talk to each other using mount shared volume policy-data → `/var/ztfp/policies`.
- policy.json is sent to control plane, which converts it to sqlite3 db and places at location for Datapath(Go) code to read. dataplance(Go) runs a seperate watcher goroutine to watch the policy update(fsnotify)

1. Service [controlplane](./ControlPlane_DataPlane/). controlplane/Dockerfile. Port: 8090. Upload JSON → compile policy.db
2. ztfp. Image(root Dockerfile), ports: 8080, 9090. Forward proxy + metrics 

```json
{
  "tenant_id": 1,
  "default_action": "ALLOW",
  "policies": {
    "rtp": {
      "rules": [
        {
          "id": "rtp-block-social",
          "name": "Block social media",
          "priority": 10,
          "conditions": {
            "domains": ["(facebook|instagram|twitter|tiktok)\\.com$"],
            "methods": ["GET", "POST"],
            "saml_groups": ["all-employees"]
          }
          "action": "BLOCK",
          "message": "Social media blocked by RTP policy"
        },
        {
          "id": "rtp-dlp-internal",
          "name": "DLP on internal uploads",
          "priority": 20,
          "conditions": {
            "domains": [".*\\.internal\\.example\\.com$"],
            "methods": ["POST", "PUT"],
            "content_direction": "upload",
            "saml_groups": ["engineering", "finance"]
          },
          "inspect": {
            "dlp": true
          },
          "action": "ALLOW",
          "scan_fallback": "fallback_block",
          "message": "Internal upload scanned for sensitive data"
        },
        {
          "id": "rtp-mcp-api",
          "name": "MCP tool inspection",
          "priority": 30,
          "conditions": 
            "domains": ["api\\.openai\\.com$"],
            "methods": ["POST"]

          }
          "inspect": {
            "mcp": {
              "tool_names": ["file_.*", "shell_.*"],
              "message_types": ["tool_call"]
            }
          },
          "action": "BLOCK",
          "scan_fallback": "fallback_alert",
          "message": "Blocked MCP tool usage"
        }
      ]
    }
  }
}
```

2. Data plane(Go code) reads the policy, creates its AST and takes policy decisions on run time when packet comes from tenant.

- Rule matching is first-match-wins.
- `user` can be exact or `*`.
- `domain` supports:
  - exact: `example.com`
  - wildcard suffix: `*.example.com`
  - global wildcard: `*`
- If no rule matches, `default_action` is used.

### Actios
**Allow**

* On action=Allow, request is forwarded to destination server
* As response is received from destination server, response is returned to client

**Block**

* Request is dropped at proxy and a coaching message is sent to client (HTTP path) or denied for CONNECT

### In-depth evaluate() decision flow
* Whenever a request arrives at proxy handlers (`handleHTTP` / `handleConnect`), both paths call:
  * `func (s *Server) evaluate(r *http.Request) (user, domain string, blocked bool, status int, reason string, viol []inspector.Violation)`

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

<a name=ps></a>
## Policy Structure
From above json this is how policy is stored in AST inside go module
Per tenant information storage:

```go
type TenantPolicy struct {
	TenantID        int64
	DefaultAction   Action
	EvaluationOrder []string
	Rules           []RuleRecord
	ast             *PolicyAST
	mu              sync.RWMutex
}
tp TenantPolicy

// Read all rows from db
rows, err := db.Query(`
  SELECT id, policy_type, priority, name, action, message,
          conditions_json, inspect_json, scan_fallback, ssl_mode, isolation
  FROM rules
  ORDER BY policy_type, priority, id
`)

for rows.Next() {
  if err := rows.Scan(
    &rec.ID, &rec.PolicyType, &rec.Priority, &rec.Name, &rec.Action, &rec.Message,
    &conditions, &inspectRaw, &scanFallback, &sslMode, &isolation,
  );
  tp.Rules = append(tp.Rules, rec)
}
```