package config

import (
	"os"
	"testing"
)

func TestPolicyDirEnvOverride(t *testing.T) {
	t.Setenv("ZTFP_POLICY_DIR", "/tmp/custom-policies")
	t.Setenv("ZTFP_TENANT_MODE", "strict")
	t.Setenv("ZTFP_DEFAULT_TENANT", "3")

	cfg, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PolicyDir != "/tmp/custom-policies" {
		t.Fatalf("PolicyDir: got %q", cfg.PolicyDir)
	}
	if cfg.TenantMode != "strict" {
		t.Fatalf("TenantMode: got %q", cfg.TenantMode)
	}
	if cfg.DefaultTenantID != 3 {
		t.Fatalf("DefaultTenantID: got %d", cfg.DefaultTenantID)
	}
}

func TestDefaultPolicyDir(t *testing.T) {
	_ = os.Unsetenv("ZTFP_POLICY_DIR")
	cfg := Default()
	if cfg.PolicyDir != "/var/ztfp/policies/" {
		t.Fatalf("default PolicyDir: got %q", cfg.PolicyDir)
	}
	if cfg.TenantMode != "dev" {
		t.Fatalf("default TenantMode: got %q", cfg.TenantMode)
	}
	if cfg.DefaultTenantID != 1 {
		t.Fatalf("default DefaultTenantID: got %d", cfg.DefaultTenantID)
	}
}
