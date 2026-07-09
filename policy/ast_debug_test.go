package policy

import (
	"testing"
)

func TestASTSummary(t *testing.T) {
	dir := t.TempDir()
	path := writeTestPolicyDB(t, dir, 1, "")

	tp, err := LoadFromDB(path, 1)
	if err != nil {
		t.Fatal(err)
	}

	summary := tp.ASTSummary()
	if summary.RuleCount != 1 {
		t.Fatalf("rule_count=%d", summary.RuleCount)
	}
	rtp, ok := summary.PolicyTypes["rtp"]
	if !ok || len(rtp) != 1 {
		t.Fatalf("expected rtp rules in AST summary")
	}
	if len(rtp[0].DomainRegex) == 0 {
		t.Fatal("expected compiled domain regex in summary")
	}
}
