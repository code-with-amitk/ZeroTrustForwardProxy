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
