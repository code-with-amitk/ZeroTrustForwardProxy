// Package policy tests deterministic rule-matching behavior.
//
// Architecture fit:
// - Protects policy engine regex domain matching and condition evaluation.
//
// Key responsibilities:
// - Validate regex domain pattern matching outcomes.
// - Validate method-based matching.
// - Validate rule action decisions.
package policy

import (
	"regexp"
	"testing"
)

// TestMatchesDomainCondition checks regex domain pattern matching behavior.
//
// Inputs:
// - Table-driven set of pattern/domain pairs.
//
// Outputs:
// - Test pass/fail based on expected match result.
//
// Side effects:
// - None.
func TestMatchesDomainCondition(t *testing.T) {
	tests := []struct {
		pattern string
		domain  string
		want    bool
	}{
		{`^example\.com$`, "example.com", true},
		{`^example\.com$`, "api.example.com", false},
		{`.*\.example\.com$`, "api.example.com", true},
		{`(facebook|instagram|twitter)\.com$`, "facebook.com", true},
		{`(facebook|instagram|twitter)\.com$`, "linkedin.com", false},
	}
	for _, tt := range tests {
		pattern, err := regexp.Compile(tt.pattern)
		if err != nil {
			t.Fatalf("failed to compile pattern %s: %v", tt.pattern, err)
		}

		got := pattern.MatchString(tt.domain)
		if got != tt.want {
			t.Fatalf("pattern=%s domain=%s got=%v want=%v", tt.pattern, tt.domain, got, tt.want)
		}
	}
}

// TestMatchesMethodCondition checks method matching behavior.
//
// Inputs:
// - Table-driven set of method conditions and request methods.
//
// Outputs:
// - Test pass/fail based on expected match result.
func TestMatchesMethodCondition(t *testing.T) {
	tests := []struct {
		methods []string
		method  string
		want    bool
	}{
		{[]string{"GET"}, "GET", true},
		{[]string{"GET"}, "POST", false},
		{[]string{"GET", "POST"}, "POST", true},
		{[]string{}, "GET", true}, // Empty methods match all
	}
	for _, tt := range tests {
		cond := Conditions{Methods: tt.methods}
		got := matchesMethodCondition(cond, tt.method)
		if got != tt.want {
			t.Fatalf("methods=%v method=%s got=%v want=%v", tt.methods, tt.method, got, tt.want)
		}
	}
}

// TestDecideWithRegexDomains checks policy decision with regex domain patterns.
func TestDecideWithRegexDomains(t *testing.T) {
	pattern1, _ := regexp.Compile(`^example\.com$`)
	pattern2, _ := regexp.Compile(`.*\.internal\.example\.com$`)

	engine := Engine{
		cfg: Config{
			DefaultAction: string(ActionBlock),
			Rules: []Rule{
				{
					Id:   "1",
					Name: "allow-example",
					Conditions: Conditions{
						Domains:  []string{`^example\.com$`},
						Compiled: []*regexp.Regexp{pattern1},
					},
					Action:  ActionAllow,
					Message: "Example.com allowed",
				},
				{
					Id:   "2",
					Name: "block-internal",
					Conditions: Conditions{
						Domains:  []string{`.*\.internal\.example\.com$`},
						Compiled: []*regexp.Regexp{pattern2},
					},
					Action:  ActionBlock,
					Message: "Internal domains blocked",
				},
			},
		},
	}

	// Test allow rule
	action, msg := engine.Decide("example.com", "GET")
	if action != ActionAllow {
		t.Fatalf("expected ActionAllow for example.com, got %v", action)
	}
	if msg != "Example.com allowed" {
		t.Fatalf("expected correct message, got %q", msg)
	}

	// Test block rule
	action, msg = engine.Decide("api.internal.example.com", "GET")
	if action != ActionBlock {
		t.Fatalf("expected ActionBlock for internal domain, got %v", action)
	}
	if msg != "Internal domains blocked" {
		t.Fatalf("expected correct message, got %q", msg)
	}

	// Test default action for non-matching domain
	action, _ = engine.Decide("unknown.com", "GET")
	if action != ActionBlock {
		t.Fatalf("expected default ActionBlock for unknown domain, got %v", action)
	}
}

// TestDecideWithMethodConditions checks policy decision with method conditions.
func TestDecideWithMethodConditions(t *testing.T) {
	patternAll, _ := regexp.Compile(`.*`)

	engine := Engine{
		cfg: Config{
			DefaultAction: string(ActionAllow),
			Rules: []Rule{
				{
					Id:   "1",
					Name: "inspect-post-requests",
					Conditions: Conditions{
						Domains:  []string{`.*`},
						Methods:  []string{"POST", "PUT"},
						Compiled: []*regexp.Regexp{patternAll},
					},
					Action:  ActionInspectDLP,
					Message: "POST/PUT requests inspected",
				},
			},
		},
	}

	// POST request should be inspected
	action, _ := engine.Decide("example.com", "POST")
	if action != ActionInspectDLP {
		t.Fatalf("expected ActionInspectDLP for POST, got %v", action)
	}

	// GET request should use default action
	action, _ = engine.Decide("example.com", "GET")
	if action != ActionAllow {
		t.Fatalf("expected default ActionAllow for GET, got %v", action)
	}
}
