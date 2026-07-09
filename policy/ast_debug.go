package policy

import (
	"encoding/json"
	"fmt"
	"strings"

	"go.uber.org/zap"
)

// ASTRuleSummary is a log-friendly view of one indexed rule in the AST.
type ASTRuleSummary struct {
	ID           string   `json:"id"`
	Priority     int      `json:"priority"`
	Action       string   `json:"action"`
	Message      string   `json:"message,omitempty"`
	DomainRegex  []string `json:"domain_regex,omitempty"`
	DestRegex    []string `json:"dest_regex,omitempty"`
	Methods      []string `json:"methods,omitempty"`
	InspectDLP   bool     `json:"inspect_dlp,omitempty"`
	SSLMode      string   `json:"ssl_mode,omitempty"`
	Isolation    string   `json:"isolation,omitempty"`
	ScanFallback string   `json:"scan_fallback,omitempty"`
}

// ASTSummary is a serializable snapshot of TenantPolicy + AST for debugging.
type ASTSummary struct {
	TenantID        int64                       `json:"tenant_id"`
	DefaultAction   string                      `json:"default_action"`
	EvaluationOrder []string                    `json:"evaluation_order"`
	RuleCount       int                         `json:"rule_count"`
	PolicyTypes     map[string][]ASTRuleSummary `json:"policy_types"`
}

// ASTSummary builds a debug snapshot from the loaded tenant policy.
func (tp *TenantPolicy) ASTSummary() ASTSummary {
	tp.mu.RLock()
	defer tp.mu.RUnlock()

	out := ASTSummary{
		TenantID:        tp.TenantID,
		DefaultAction:   string(tp.DefaultAction),
		EvaluationOrder: append([]string(nil), tp.EvaluationOrder...),
		RuleCount:       len(tp.Rules),
		PolicyTypes:     make(map[string][]ASTRuleSummary),
	}
	if tp.ast == nil {
		return out
	}

	order := tp.EvaluationOrder
	if len(order) == 0 {
		order = policyTypeOrder
	}
	for _, ptype := range order {
		rules := tp.ast.ASTMap[ptype]
		if len(rules) == 0 {
			continue
		}
		summaries := make([]ASTRuleSummary, 0, len(rules))
		for _, ir := range rules {
			rec := ir.record
			s := ASTRuleSummary{
				ID:           rec.ID,
				Priority:     rec.Priority,
				Action:       rec.Action,
				Message:      rec.Message,
				Methods:      rec.Conditions.Methods,
				InspectDLP:   rec.Inspect.DLP,
				SSLMode:      rec.SSLMode,
				Isolation:    rec.Isolation,
				ScanFallback: rec.ScanFallback,
			}
			for _, re := range ir.domains {
				s.DomainRegex = append(s.DomainRegex, re.String())
			}
			for _, re := range ir.dests {
				s.DestRegex = append(s.DestRegex, re.String())
			}
			summaries = append(summaries, s)
		}
		out.PolicyTypes[ptype] = summaries
	}
	return out
}

// LogAST prints the AST summary as structured logs.
func (tp *TenantPolicy) LogAST(logger *zap.SugaredLogger) {
	if logger == nil {
		return
	}
	summary := tp.ASTSummary()
	raw, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		logger.Warnw("failed to marshal AST summary", "error", err)
		return
	}
	logger.Infow("tenant policy AST loaded",
		"tenant_id", summary.TenantID,
		"rule_count", summary.RuleCount,
		"default_action", summary.DefaultAction,
		"evaluation_order", strings.Join(summary.EvaluationOrder, " → "),
	)
	logger.Infof("policy AST:\n%s", string(raw))
}

// FormatAST returns a human-readable AST dump string.
func (tp *TenantPolicy) FormatAST() string {
	raw, err := json.MarshalIndent(tp.ASTSummary(), "", "  ")
	if err != nil {
		return fmt.Sprintf("marshal AST: %v", err)
	}
	return string(raw)
}
