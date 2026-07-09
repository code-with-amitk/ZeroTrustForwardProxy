package policy

import (
	"encoding/json"
	"regexp"
	"sync"
)

const schemaVersionV2 = "2"

var policyTypeOrder = []string{"bypass", "egress_ip", "enterprise_browser", "rtp"}

// TenantPolicy holds one tenant's compiled in-memory policy (rules + AST).
type TenantPolicy struct {
	TenantID        int64
	DefaultAction   Action
	EvaluationOrder []string
	Rules           []RuleRecord
	ast             *PolicyAST
	mu              sync.RWMutex
}

// RuleRecord is a hydrated row from policy.db before / after AST indexing.
type RuleRecord struct {
	ID           string
	PolicyType   string
	Priority     int
	Name         string
	Action       string
	Message      string
	Conditions   RuleConditions
	Inspect      InspectConfig
	ScanFallback string
	SSLMode      string
	Isolation    string
}

// RuleConditions mirrors deserialized conditions_json.
type RuleConditions struct {
	Domains      []string `json:"domains"`
	Methods      []string `json:"methods"`
	Groups       []string `json:"groups"`
	SAMLGroups   []string `json:"saml_groups"`
	EgressIPs    []string `json:"egress_ips"`
	Destinations []string `json:"destinations"`
	Protocols    []string `json:"protocols"`
}

// InspectConfig mirrors inspect_json from RTP rules.
type InspectConfig struct {
	DLP bool            `json:"dlp"`
	MCP json.RawMessage `json:"mcp"`
}

// PolicyAST indexes rules for fast Decide() traversal.
//
// One PolicyAST exists per TenantPolicy (per tenant in the LRU cache).
// ASTMap groups that tenant's rules by policy_type; see buildAST in ast.go.
type PolicyAST struct {
	// Key = policy_type ("rtp", "bypass", "egress_ip", "enterprise_browser")
	// Value = ordered list of indexed rules for that type
	ASTMap map[string][]*indexedRule
}

// indexedRule is one policy rule after regex compilation for hot-path matching.
// The full SQLite/JSON fields live in record; domains/dests are compiled matchers.
type indexedRule struct {
	record  RuleRecord
	domains []*regexp.Regexp
	dests   []*regexp.Regexp
}
