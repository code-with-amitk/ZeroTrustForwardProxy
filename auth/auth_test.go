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
	const tenantID int64 = 1
	tenantDir := filepath.Join(dir, "1")
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
	token, err := jwt.GenerateJWT(nil, "alice", tenantID)
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
	if id.TenantID != tenantID {
		t.Fatalf("tenant: got %d want %d", id.TenantID, tenantID)
	}
}

func TestExtractMissingTenantStrict(t *testing.T) {
	cfg := config.Default()
	cfg.TenantMode = "strict"
	cfg.PolicyDir = t.TempDir()

	v := NewJWTValidator(nil, cfg)
	token, err := jwt.GenerateJWT(nil, "alice", 0)
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
	cfg.DefaultTenantID = 1
	cfg.PolicyDir = t.TempDir()

	v := NewJWTValidator(nil, cfg)
	token, err := jwt.GenerateJWT(nil, "bob", 0)
	if err != nil {
		t.Fatal(err)
	}

	r, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
	r.Header.Set("Authorization", "Bearer "+token)

	id, err := v.ExtractAuthorizationnHeader(r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id.TenantID != 1 {
		t.Fatalf("tenant: got %d want 1", id.TenantID)
	}
}

func TestExtractUnknownTenantStrict(t *testing.T) {
	cfg := config.Default()
	cfg.TenantMode = "strict"
	cfg.PolicyDir = t.TempDir()

	v := NewJWTValidator(nil, cfg)
	token, err := jwt.GenerateJWT(nil, "alice", 999)
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
	if TenantPolicyExists(dir, 2) {
		t.Fatal("expected missing tenant")
	}
	tenantDir := filepath.Join(dir, "2")
	if err := os.MkdirAll(tenantDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tenantDir, "policy.db"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !TenantPolicyExists(dir, 2) {
		t.Fatal("expected tenant policy to exist")
	}
}

func TestTenantDirName(t *testing.T) {
	if TenantDirName(42) != "42" {
		t.Fatalf("got %q", TenantDirName(42))
	}
}
