# DLP Engine Design

```mermaid
flowchart LR
    B[Request/Response Body] --> L[Read up to max_inspect_body_bytes]
    L --> R1[Regex: credit card pattern]
    L --> R2[Regex: api_key/secret/token pattern]
    R1 --> V[Violation list]
    R2 --> V
    V -->|non-empty| BL[Block or log violation]
    V -->|empty| AL[Allow traffic]
```

## Detection Approach
- No external DLP library is used in this implementation.
- Detection is regex-based:
  - Credit-card-like number pattern (`13-16` digits with optional spaces/hyphens)
  - Secret pattern (`api_key`, `secret`, `token` followed by value)
- Body is restored after inspection so forwarding still works.

## Extensibility
- You can plug in external engines (e.g. Hyperscan, custom ML, SaaS DLP APIs) by replacing `inspector.Inspector`.
