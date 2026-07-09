package policy

import (
	"fmt"
	"regexp"
	"sort"
)

// buildAST compiles a flat []RuleRecord (one tenant's rows from policy.db) into a PolicyAST.
//
// # How policy is stored per tenant
//
// Tenant 1 and tenant 2 each get their own TenantPolicy and their own ASTMap.
// tenant 1: TenantPolicy { TenantID: 1, ast.ASTMap["rtp"] → [...] }
// tenant 2: TenantPolicy { TenantID: 2, ast.ASTMap["rtp"] → [...] }

// ASTMap: map[string][]*indexedRule
// Keys   → "rtp" | "bypass" | "egress_ip" | "enterprise_browser"
// Values → slice of rules, sorted by priority (10 before 20)

//	ASTMap
//	┌──────────────────────────────────────────────────────────────────────────┐
//	│  key "rtp"  ──►  [0] *indexedRule                                        │
//	│                    ├─ record.id          = "rtp-block-social"          │
//	│                    ├─ record.priority    = 10                            │
//	│                    ├─ record.action      = "BLOCK"                       │
//	│                    ├─ record.message     = "Social media blocked…"       │
//	│                    ├─ record.Conditions.Methods = ["GET","POST"]         │
//	│                    ├─ record.Conditions.SAMLGroups = ["all-employees"]   │
//	│                    └─ domains[]        = [/(facebook|…)\.com$/]       │
//	│                  [1] *indexedRule  (rtp-dlp-internal, priority 20)       │
//	│                    ├─ record.inspect.dlp = true                          │
//	│                    ├─ record.scan_fallback = "fallback_block"            │
//	│                    └─ domains[]        = [/.*\.internal\.example\.com$/] │
//	│  key "bypass"     ──► (empty slice if no bypass rules in this tenant)    │
//	│  key "egress_ip"  ──► …                                                  │
//	└──────────────────────────────────────────────────────────────────────────┘
//
//	TenantPolicy (same object, outside ASTMap):
//	  TenantID=1, DefaultAction=ALLOW, EvaluationOrder=[bypass→egress_ip→…→rtp]
//
// Decide() walks EvaluationOrder, then each ASTMap[ptype] slice in priority order.
func buildAST(rules []RuleRecord) (*PolicyAST, error) {
	ast := &PolicyAST{ASTMap: make(map[string][]*indexedRule)}
	grouped := make(map[string][]RuleRecord)
	for _, r := range rules {
		// key(type) = rtp, egress_ip, enterprise_browser, bypass
		// value = []RuleRecord
		grouped[r.PolicyType] = append(grouped[r.PolicyType], r)
	}

	for ptype, recs := range grouped {
		// sort by priority and id
		sort.SliceStable(recs, func(i, j int) bool {
			if recs[i].Priority != recs[j].Priority {
				return recs[i].Priority < recs[j].Priority
			}
			return recs[i].ID < recs[j].ID
		})
		indexed := make([]*indexedRule, 0, len(recs))
		for _, rec := range recs {
			ir := &indexedRule{record: rec}
			for _, p := range domainPatterns(rec) {
				re, err := regexp.Compile(p)
				if err != nil {
					return nil, fmt.Errorf("rule %s/%s domain pattern %q: %w", ptype, rec.ID, p, err)
				}
				ir.domains = append(ir.domains, re)
			}
			for _, p := range rec.Conditions.Destinations {
				re, err := regexp.Compile(p)
				if err != nil {
					return nil, fmt.Errorf("rule %s/%s destination %q: %w", ptype, rec.ID, p, err)
				}
				ir.dests = append(ir.dests, re)
			}
			indexed = append(indexed, ir)
		}
		ast.ASTMap[ptype] = indexed
	}
	return ast, nil
}

func domainPatterns(rec RuleRecord) []string {
	if len(rec.Conditions.Domains) > 0 {
		return rec.Conditions.Domains
	}
	if len(rec.Conditions.Destinations) > 0 {
		return rec.Conditions.Destinations
	}
	return nil
}
