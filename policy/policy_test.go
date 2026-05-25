// Package policy tests deterministic rule-matching behavior.
//
// Architecture fit:
// - Protects policy engine wildcard domain semantics used by proxy enforcement.
//
// Key responsibilities:
// - Validate exact and wildcard domain matching outcomes.
package policy

import "testing"

// TestMatchesDomain checks wildcard and exact domain predicate behavior.
//
// Inputs:
// - Table-driven set of pattern/domain pairs.
//
// Outputs:
// - Test pass/fail based on expected match result.
//
// Side effects:
// - None.
func TestMatchesDomain(t *testing.T) {
	tests := []struct {
		pattern string
		domain  string
		want    bool
	}{
		{"*.example.com", "api.example.com", true},
		{"example.com", "example.com", true},
		{"*.example.com", "example.net", false},
	}
	for _, tt := range tests {
		// Execute internal domain matcher with test case values.
		got := matchesDomain(tt.pattern, tt.domain)
		// Assert matcher output equals expected truth value.
		if got != tt.want {
			t.Fatalf("pattern=%s domain=%s got=%v want=%v", tt.pattern, tt.domain, got, tt.want)
		}
	}
}

func TestDecideWithHostnameAndProtocol(t *testing.T) {
	engine := Engine{cfg: Config{DefaultAction: string(Block), Rules: []Rule{
		{User: "mcp-agent", Hostname: "mcp-provider1.com", Protocol: "HTTP+MCP", Version: "2025-11-09", Action: string(Allow)},
	}}}

	if got := engine.Decide("mcp-agent", "api.example.com", "mcp-provider1.com", "HTTP+MCP", "2025-11-09"); got != Allow {
		t.Fatalf("expected allow for matching hostname/protocol/version, got %v", got)
	}

	if got := engine.Decide("mcp-agent", "api.example.com", "mcp-provider1.com", "HTTP+MCP", "2025-11-10"); got != Block {
		t.Fatalf("expected block for non-matching version, got %v", got)
	}

	if got := engine.Decide("mcp-agent", "api.example.com", "other-provider.com", "HTTP+MCP", "2025-11-09"); got != Block {
		t.Fatalf("expected block for non-matching hostname, got %v", got)
	}
}
