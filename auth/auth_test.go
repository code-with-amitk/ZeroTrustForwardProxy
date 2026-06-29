package auth

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"zerotrust-forward-proxy/config"
	"zerotrust-forward-proxy/jwt"
)

func TestExtractWithTenantIDStrict(t *testing.T) {
	dir := t.TempDir()
	tenantDir := filepath.Join(dir, "acme")
	if err := os.MkdirAll(tenantDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tenantDir, "policy.db"), []byte("sqlite"), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg := config.Default()
	cfg.TenantMode = "strict"
	cfg.PolicyDir = dir

	v := NewJWTValidator(nil, cfg)
	token, err := jwt.GenerateJWT(nil, "alice", "acme")
	if err != nil {
		t.Fatal(err)
	}

	r, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
	r.Header.Set("Authorization", "Bearer "+token)

	id, err := v.ExtractAuthorizationnHeader(r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id.User != "alice" {
		t.Fatalf("user: got %q want alice", id.User)
	}
	if id.TenantID != "acme" {
		t.Fatalf("tenant: got %q want acme", id.TenantID)
	}
}

func TestExtractMissingTenantStrict(t *testing.T) {
	cfg := config.Default()
	cfg.TenantMode = "strict"
	cfg.PolicyDir = t.TempDir()

	v := NewJWTValidator(nil, cfg)
	token, err := jwt.GenerateJWT(nil, "alice", "")
	if err != nil {
		t.Fatal(err)
	}

	r, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
	r.Header.Set("Authorization", "Bearer "+token)

	_, err = v.ExtractAuthorizationnHeader(r)
	if err == nil {
		t.Fatal("expected error for missing tenant in strict mode")
	}
	if err != ErrMissingTenant {
		t.Fatalf("got %v want ErrMissingTenant", err)
	}
}

func TestExtractMissingTenantDevFallback(t *testing.T) {
	cfg := config.Default()
	cfg.TenantMode = "dev"
	cfg.DefaultTenant = "default"
	cfg.PolicyDir = t.TempDir()

	v := NewJWTValidator(nil, cfg)
	token, err := jwt.GenerateJWT(nil, "bob", "")
	if err != nil {
		t.Fatal(err)
	}

	r, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
	r.Header.Set("Authorization", "Bearer "+token)

	id, err := v.ExtractAuthorizationnHeader(r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id.TenantID != "default" {
		t.Fatalf("tenant: got %q want default", id.TenantID)
	}
}

func TestExtractUnknownTenantStrict(t *testing.T) {
	cfg := config.Default()
	cfg.TenantMode = "strict"
	cfg.PolicyDir = t.TempDir()

	v := NewJWTValidator(nil, cfg)
	token, err := jwt.GenerateJWT(nil, "alice", "unknown-tenant")
	if err != nil {
		t.Fatal(err)
	}

	r, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
	r.Header.Set("Authorization", "Bearer "+token)

	_, err = v.ExtractAuthorizationnHeader(r)
	if err == nil {
		t.Fatal("expected unknown tenant error")
	}
	if err != ErrUnknownTenant {
		t.Fatalf("got %v want ErrUnknownTenant", err)
	}
}

func TestTenantPolicyExists(t *testing.T) {
	dir := t.TempDir()
	if TenantPolicyExists(dir, "acme") {
		t.Fatal("expected missing tenant")
	}
	tenantDir := filepath.Join(dir, "acme")
	if err := os.MkdirAll(tenantDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tenantDir, "policy.db"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !TenantPolicyExists(dir, "acme") {
		t.Fatal("expected tenant policy to exist")
	}
}
