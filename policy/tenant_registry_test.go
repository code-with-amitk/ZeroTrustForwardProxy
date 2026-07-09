package policy

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

func writeTestPolicyDB(t *testing.T, dir string, tenantID int64, blockDomain string) string {
	t.Helper()
	tdir := filepath.Join(dir, "1")
	if tenantID != 1 {
		tdir = filepath.Join(dir, "42")
	}
	if err := os.MkdirAll(tdir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(tdir, "policy.db")
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	_, err = db.Exec(`
		CREATE TABLE policy_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
		CREATE TABLE rules (
			id TEXT NOT NULL,
			policy_type TEXT NOT NULL,
			priority INTEGER NOT NULL,
			name TEXT,
			action TEXT NOT NULL,
			message TEXT,
			conditions_json TEXT NOT NULL,
			inspect_json TEXT,
			scan_fallback TEXT,
			ssl_mode TEXT,
			isolation TEXT,
			PRIMARY KEY (policy_type, id)
		);
		INSERT INTO policy_meta(key,value) VALUES ('schema_version','2');
		INSERT INTO policy_meta(key,value) VALUES ('default_action','ALLOW');
		INSERT INTO policy_meta(key,value) VALUES ('evaluation_order','["bypass","egress_ip","enterprise_browser","rtp"]');
		INSERT INTO rules(id,policy_type,priority,name,action,message,conditions_json,inspect_json,scan_fallback,ssl_mode,isolation)
		VALUES ('block-social','rtp',10,'block social','BLOCK','blocked','{"domains":["(facebook|twitter)\\.com$"],"methods":["GET"]}','','','','');
	`)
	if err != nil {
		t.Fatal(err)
	}
	if blockDomain != "" {
		_, err = db.Exec(`
			INSERT INTO rules(id,policy_type,priority,name,action,message,conditions_json,inspect_json,scan_fallback,ssl_mode,isolation)
			VALUES ('extra','rtp',20,'extra','BLOCK','extra block',?, '','','','','')
		`, `{"domains":["`+blockDomain+`"]}`)
		if err != nil {
			t.Fatal(err)
		}
	}
	return path
}

func TestLoadFromDBAndDecide(t *testing.T) {
	dir := t.TempDir()
	path := writeTestPolicyDB(t, dir, 1, "")

	tp, err := LoadFromDB(path, 1)
	if err != nil {
		t.Fatal(err)
	}

	action, msg := tp.Decide("www.facebook.com", "GET")
	if action != ActionBlock || msg != "blocked" {
		t.Fatalf("got action=%v msg=%q", action, msg)
	}

	action, _ = tp.Decide("example.com", "GET")
	if action != ActionAllow {
		t.Fatalf("expected allow default, got %v", action)
	}
}

func TestRegistryColdLoadAndLRU(t *testing.T) {
	dir := t.TempDir()
	writeTestPolicyDB(t, dir, 1, "")

	reg := NewRegistry(RegistryConfig{
		PolicyDir:   dir,
		CacheSize:   1,
		LoadWorkers: 2,
	}, nil)
	defer reg.Close()

	if reg.CacheSize() != 0 {
		t.Fatalf("expected empty cache at start, got %d", reg.CacheSize())
	}

	action, _, err := reg.Decide(1, "facebook.com", "GET")
	if err != nil {
		t.Fatal(err)
	}
	if action != ActionBlock {
		t.Fatalf("expected block, got %v", action)
	}
	if reg.CacheSize() != 1 {
		t.Fatalf("expected cache size 1, got %d", reg.CacheSize())
	}

	// tenant 42 has no policy.db
	_, _, err = reg.Decide(42, "example.com", "GET")
	if err != ErrPolicyNotFound {
		t.Fatalf("expected ErrPolicyNotFound, got %v", err)
	}
}

func TestRegistryReloadSwap(t *testing.T) {
	dir := t.TempDir()
	writeTestPolicyDB(t, dir, 1, "")

	reg := NewRegistry(RegistryConfig{PolicyDir: dir, CacheSize: 10, LoadWorkers: 1}, nil)
	defer reg.Close()

	_, _, err := reg.Decide(1, "example.com", "GET")
	if err != nil {
		t.Fatal(err)
	}

	// add stricter rule
	path := filepath.Join(dir, "1", "policy.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`
		INSERT INTO rules(id,policy_type,priority,name,action,message,conditions_json,inspect_json,scan_fallback,ssl_mode,isolation)
		VALUES ('block-example','rtp',5,'block example','BLOCK','no example','{"domains":["^example\\.com$"]}','','','','')
	`)
	db.Close()
	if err != nil {
		t.Fatal(err)
	}

	if err := reg.ReloadTenant(1); err != nil {
		t.Fatal(err)
	}
	action, msg, err := reg.Decide(1, "example.com", "GET")
	if err != nil {
		t.Fatal(err)
	}
	if action != ActionBlock || msg != "no example" {
		t.Fatalf("after reload got action=%v msg=%q", action, msg)
	}
}

func TestLoadFromDBRealSample(t *testing.T) {
	sample := filepath.Join("..", "testdata", "sample_policy_rtp.json")
	dbPath := filepath.Join("..", "testdata", "sample_policy_rtp.db")
	if _, err := os.Stat(sample); err != nil {
		t.Skip("sample json missing")
	}

	// compile via controlplane if db not present
	if _, err := os.Stat(dbPath); err != nil {
		t.Skip("run: cd controlplane && python -m policy_compiler.cli ../testdata/sample_policy_rtp.json")
	}

	tp, err := LoadFromDB(dbPath, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(tp.Rules) == 0 {
		t.Fatal("expected rules")
	}
}
