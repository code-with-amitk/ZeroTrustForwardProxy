package policy

import (
	"encoding/json"
	"strings"
)

// Decide evaluates policy for domain/method under a read lock on the AST.
func (tp *TenantPolicy) Decide(domain, method string) (Action, string) {
	tp.mu.RLock()
	defer tp.mu.RUnlock()

	if tp.ast == nil {
		return tp.DefaultAction, ""
	}

	domain = strings.ToLower(domain)
	method = strings.ToUpper(method)

	order := tp.EvaluationOrder
	if len(order) == 0 {
		order = policyTypeOrder
	}

	for _, ptype := range order {
		rules := tp.ast.ASTMap[ptype]
		for _, ir := range rules {
			if !matchesRule(ir, domain, method) {
				continue
			}
			action, msg := terminalToProxyAction(ir.record)
			if strings.EqualFold(ir.record.Action, "CONTINUE") {
				continue
			}
			return action, msg
		}
	}
	return tp.DefaultAction, ""
}

func matchesRule(ir *indexedRule, domain, method string) bool {
	rec := ir.record
	if len(ir.domains) > 0 {
		matched := false
		for _, re := range ir.domains {
			if re.MatchString(domain) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	} else if len(ir.dests) > 0 {
		matched := false
		for _, re := range ir.dests {
			if re.MatchString(domain) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	if len(rec.Conditions.Methods) > 0 {
		ok := false
		for _, m := range rec.Conditions.Methods {
			if strings.EqualFold(m, method) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

func terminalToProxyAction(rec RuleRecord) (Action, string) {
	if rec.PolicyType == "rtp" && rec.Inspect.DLP {
		return ActionInspectDLP, rec.Message
	}
	if rec.PolicyType == "rtp" && len(rec.Inspect.MCP) > 0 {
		var asBool bool
		if json.Unmarshal(rec.Inspect.MCP, &asBool) == nil && asBool {
			return ActionInspectMCP, rec.Message
		}
		var mcpObj map[string]interface{}
		if json.Unmarshal(rec.Inspect.MCP, &mcpObj) == nil && len(mcpObj) > 0 {
			return ActionInspectMCP, rec.Message
		}
	}

	switch strings.ToUpper(rec.Action) {
	case "BLOCK":
		return ActionBlock, rec.Message
	case "COACH":
		return ActionCoach, rec.Message
	case "INSPECT_DLP":
		return ActionInspectDLP, rec.Message
	case "INSPECT_MCP":
		return ActionInspectMCP, rec.Message
	default:
		return mapTerminalAction(rec.Action), rec.Message
	}
}

// Swap replaces the in-memory policy atomically (used on reload).
func (tp *TenantPolicy) Swap(next *TenantPolicy) {
	if next == nil {
		return
	}
	tp.mu.Lock()
	defer tp.mu.Unlock()
	tp.DefaultAction = next.DefaultAction
	tp.EvaluationOrder = next.EvaluationOrder
	tp.Rules = next.Rules
	tp.ast = next.ast
}
