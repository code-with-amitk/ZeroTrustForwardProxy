
- [Control Plane Metrics](#control-plane-metrics)
  * [Sending](#sending)
  * [Cost](#cost)
- [Dataplane Metrics](#dataplane-metrics)
  * [Wire](#wire)
  * [Sent from Process](#sent-from-process)


# Metrics(Json > sqldb > zip)
```
Tenant UI
    │  policy.json  (once)
    ▼
Control plane  ── compile + zip ──► policy.db.zip
    │
    │  fan-out × N POPs
    ├──────────────► POP 1 data plane  ── unzip + LoadFromDB ──► AST
    ├──────────────► POP 2 data plane  ── unzip + LoadFromDB ──► AST
    └──────────────► POP N data plane  ── unzip + LoadFromDB ──► AST
```
## Control Plane Metrics

### Sending
| Name | Meaning |[Type(gauge/histogram/counter/summary)](https://github.com/code-with-amitk/Code-examples/blob/master/System-Design/Concepts/Logging_and_Monitoring/Prometheus/README.md)|
|---|---|---|
|Egress bytes|fanout size||
|egress_bytes_total|total bytes sent for all tenants|gauge|
|distribution pops| How many POPs this publish targeted|gauge|
|distribtution seconds total|time to finish all fanout(p50/p90)|histogram|
|distribution failures total|POP that did not get the new artifact|counter|

### Cost
| Name | Type |What it is |
|------|------|--------|
| `compile_duration_seconds` | histogram | JSON dict → `policy.db` |
| `zip_duration_seconds` | histogram | `policy.db` → zip |
| `upload_parse_duration_seconds` | histogram | Tenant UI JSON parse + schema validate (unchanged vs old) |

## Dataplane Metrics

### Wire
| Name | Meaning |type|
|---|---|---|
|ingress bytes|Bytes received from CP (zip body)|counter|
|fetch_duration_seconds|Time to pull the artifact from CP|histrogram|

### Sent from Process
| Name | Type  | What it is |
|------|------|--------|
| `load_duration_seconds` | histogram | time to load policy to AST |
| `unzip_duration_seconds` | histogram | Zip → `policy.db` |
| `load_rules_count` | gauge | Rule count loaded |
| `load_failures_total` | counter | Corrupt zip/db must not look |

