- [Policy format](#pf)
- [Policy Structure](#ps)

# Policy Engine

<a name=pf></a>
## Policy format (sqlite3 db file)
* Policy is set of rules which contains domain, user, action
* Policies are evaluated from top to bottom and checked for match

<a name=ps></a>
## Policy Structure
From `policy.json` to AST

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