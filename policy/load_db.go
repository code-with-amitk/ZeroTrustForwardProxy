package policy

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	_ "modernc.org/sqlite"
)

// LoadFromDB opens policy.db read-only, hydrates TenantPolicy, builds AST, and closes the DB.
func LoadFromDB(path string, tenantID int64) (*TenantPolicy, error) {
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("policy db: %w", err)
	}

	dsn := "file:" + path + "?mode=ro"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	defer db.Close()

	meta, err := readPolicyMeta(db)
	if err != nil {
		return nil, err
	}
	if meta["schema_version"] != schemaVersionV2 {
		return nil, fmt.Errorf("unsupported schema_version %q", meta["schema_version"])
	}

	tp := &TenantPolicy{
		TenantID:      tenantID,
		DefaultAction: mapTerminalAction(meta["default_action"]),
	}
	if orderJSON := meta["evaluation_order"]; orderJSON != "" {
		_ = json.Unmarshal([]byte(orderJSON), &tp.EvaluationOrder)
	}
	if len(tp.EvaluationOrder) == 0 {
		tp.EvaluationOrder = append([]string(nil), policyTypeOrder...)
	}

	rows, err := db.Query(`
		SELECT id, policy_type, priority, name, action, message,
		       conditions_json, inspect_json, scan_fallback, ssl_mode, isolation
		FROM rules
		ORDER BY policy_type, priority, id
	`)
	if err != nil {
		return nil, fmt.Errorf("query rules: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var (
			rec         RuleRecord
			conditions  string
			inspectRaw  sql.NullString
			scanFallback sql.NullString
			sslMode     sql.NullString
			isolation   sql.NullString
		)
		if err := rows.Scan(
			&rec.ID, &rec.PolicyType, &rec.Priority, &rec.Name, &rec.Action, &rec.Message,
			&conditions, &inspectRaw, &scanFallback, &sslMode, &isolation,
		); err != nil {
			return nil, fmt.Errorf("scan rule: %w", err)
		}
		if conditions != "" {
			_ = json.Unmarshal([]byte(conditions), &rec.Conditions)
		}
		if inspectRaw.Valid && inspectRaw.String != "" {
			_ = json.Unmarshal([]byte(inspectRaw.String), &rec.Inspect)
		}
		if scanFallback.Valid {
			rec.ScanFallback = scanFallback.String
		}
		if sslMode.Valid {
			rec.SSLMode = sslMode.String
		}
		if isolation.Valid {
			rec.Isolation = isolation.String
		}
		tp.Rules = append(tp.Rules, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	ast, err := buildAST(tp.Rules)
	if err != nil {
		return nil, err
	}
	tp.ast = ast
	return tp, nil
}

func readPolicyMeta(db *sql.DB) (map[string]string, error) {
	rows, err := db.Query(`SELECT key, value FROM policy_meta`)
	if err != nil {
		return nil, fmt.Errorf("query policy_meta: %w", err)
	}
	defer rows.Close()

	meta := make(map[string]string)
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		meta[k] = v
	}
	return meta, rows.Err()
}

func mapTerminalAction(raw string) Action {
	switch strings.ToUpper(strings.TrimSpace(raw)) {
	case "BLOCK":
		return ActionBlock
	case "COACH":
		return ActionCoach
	case "BYPASS", "FWD", "ALLOW":
		return ActionAllow
	case "CONTINUE":
		return ActionAllow
	default:
		return Action(strings.ToLower(raw))
	}
}
