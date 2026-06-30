

## Python compiler module (implemented)

Location: `controlplane/policy_compiler/`

| Step | Module | Action |
|------|--------|--------|
| Validate | `validator.py` | JSON Schema + duplicate IDs, max rules, regex syntax, max file size |
| Compile | `compiler.py` | Insert rows into SQLite with indexes |
| Store | `storage.py` | Atomic `policy.db.tmp` → `policy.db`; write JSON + `policy.meta.json` |
| API | `api/server.py` | `POST /api/v1/tenants/{tenant_id}/policy` on `:8090` (separate from proxy `:8080`) |

See `controlplane/README.md` for setup, env vars, and curl examples.

## [Setup](../../../controlplane/README.md)
- How to start control plane to listen on REST API endpoint
- Tests

## Creating db from json
This is the scenario where user generates db file from json and places it directly into `/var/ztfp/policies/{tenant_id}/`
```
amit@Amit:~/ZeroTrustForwardProxy$ cd controlplane/
amit@Amit:~/ZeroTrustForwardProxy/controlplane$ source .venv/bin/activate
(.venv) amit@Amit:~/ZeroTrustForwardProxy/controlplane$ mkdir test_policies
(.venv) amit@Amit:~/ZeroTrustForwardProxy/controlplane$ cp ../testdata/sample_policy_rtp.json test_policies/policy.json
(.venv) amit@Amit:~/ZeroTrustForwardProxy/controlplane$ python -m policy_compiler.cli test_policies/
compiled 3 rules
  json: /home/amit/ZeroTrustForwardProxy/controlplane/test_policies/policy.json
  db:   /home/amit/ZeroTrustForwardProxy/controlplane/test_policies/policy.db
  meta: /home/amit/ZeroTrustForwardProxy/controlplane/test_policies/policy.meta.json
  schema_version: 2

Copy to tenant policy store, e.g.:
  mkdir -p /var/ztfp/policies/1
  cp /home/amit/ZeroTrustForwardProxy/controlplane/test_policies/policy.json /home/amit/ZeroTrustForwardProxy/controlplane/test_policies/policy.db /var/ztfp/policies/1/
(.venv) amit@Amit:~/ZeroTrustForwardProxy/controlplane$ ls -ltr test_policies/
total 32
-rw-r--r-- 1 amit amit  1609 Jun 30 17:21 policy.json
-rw-r--r-- 1 amit amit 24576 Jun 30 17:21 policy.db
-rw-r--r-- 1 amit amit   376 Jun 30 17:21 policy.meta.json
(.venv) amit@Amit:~/ZeroTrustForwardProxy/controlplane$ sqlite3 test_policies/policy.db 
SQLite version 3.37.2 2022-01-06 13:25:41
Enter ".help" for usage hints.
sqlite> .tables
policy_meta  rules      
sqlite> select * from rules;
rtp-block-social|rtp|10|Block social media|BLOCK|Social media blocked by RTP policy|{"domains": ["(facebook|instagram|twitter|tiktok)\\.com$"], "methods": ["GET", "POST"], "saml_groups": ["all-employees"]}||||
rtp-dlp-internal|rtp|20|DLP on internal uploads|ALLOW|Internal upload scanned for sensitive data|{"domains": [".*\\.internal\\.example\\.com$"], "methods": ["POST", "PUT"], "content_direction": "upload", "saml_groups": ["engineering", "finance"]}|{"dlp": true}|fallback_block||
rtp-mcp-api|rtp|30|MCP tool inspection|BLOCK|Blocked MCP tool usage|{"domains": ["api\\.openai\\.com$"], "methods": ["POST"]}|{"mcp": {"tool_names": ["file_.*", "shell_.*"], "message_types": ["tool_call"]}}|fallback_alert||
sqlite> .q
(.venv) amit@Amit:~/ZeroTrustForwardProxy/controlplane$ deactivate 
amit@Amit:~/ZeroTrustForwardProxy/controlplane$ 
```

## [Extending RTP policy conditions](../../../controlplane/docs/extending_rtp_conditions.md)