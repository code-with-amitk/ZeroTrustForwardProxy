"""Integration tests for policy control plane."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from policy_compiler.compiler import verify_sqlite_schema
from policy_compiler.normalizer import normalize_policy_document
from policy_compiler.storage import store_policy
from policy_compiler.validator import PolicyValidationError, validate_policy_document

SAMPLE_ROOT = Path(__file__).resolve().parents[2] / "testdata" / "tenant_policy_sample.json"

LEGACY_POLICY = {
    "default_action": "allow",
    "rules": [
        {
            "id": "1",
            "name": "block-social",
            "conditions": {
                "domains": ["(facebook|twitter)\\.com$"],
                "methods": ["GET"],
            },
            "action": "block",
            "message": "blocked",
            "priority": 10,
        }
    ],
}

MULTI_BLOCK_POLICY = json.loads(SAMPLE_ROOT.read_text(encoding="utf-8"))


def test_validate_rejects_string_priority():
    bad = json.loads(json.dumps(MULTI_BLOCK_POLICY))
    bad["policies"]["rtp"]["rules"][0]["priority"] = "10"
    with pytest.raises(PolicyValidationError):
        validate_policy_document(bad)


def test_validate_rejects_duplicate_rule_ids():
    doc = json.loads(json.dumps(MULTI_BLOCK_POLICY))
    dup = json.loads(json.dumps(doc["policies"]["rtp"]["rules"][0]))
    doc["policies"]["rtp"]["rules"].append(dup)
    with pytest.raises(PolicyValidationError, match="duplicate"):
        validate_policy_document(doc)


def test_legacy_flat_policy_normalizes_to_rtp_block():
    normalized = validate_policy_document(LEGACY_POLICY)
    assert "rules" not in normalized
    assert normalized["default_action"] == "ALLOW"
    rtp_rules = normalized["policies"]["rtp"]["rules"]
    assert len(rtp_rules) == 1
    assert rtp_rules[0]["action"] == "BLOCK"


def test_legacy_inspect_dlp_migrates_to_rtp_inspect():
    doc = {
        "default_action": "allow",
        "rules": [
            {
                "id": "dlp-1",
                "action": "inspect_dlp",
                "conditions": {"domains": ["example\\.com$"]},
            }
        ],
    }
    normalized = normalize_policy_document(doc)
    rule = normalized["policies"]["rtp"]["rules"][0]
    assert rule["inspect"] == {"dlp": True}
    assert rule["action"] == "ALLOW"
    assert rule["scan_fallback"] == "fallback_block"


def test_store_policy_writes_json_db_meta(tmp_path):
    stored = store_policy(tmp_path, 1, MULTI_BLOCK_POLICY)

    assert stored.json_path.exists()
    assert stored.db_path.exists()
    assert stored.meta_path.exists()
    verify_sqlite_schema(stored.db_path)

    meta = json.loads(stored.meta_path.read_text(encoding="utf-8"))
    assert meta["tenant_id"] == 1
    assert meta["rule_count"] == 6
    assert meta["version"] == 1
    assert meta["schema_version"] == "2"
    assert meta["evaluation_order"] == [
        "bypass",
        "egress_ip",
        "enterprise_browser",
        "rtp",
    ]

    conn = sqlite3.connect(stored.db_path)
    try:
        row = conn.execute(
            "SELECT value FROM policy_meta WHERE key='default_action'"
        ).fetchone()
        assert row[0] == "ALLOW"

        types = conn.execute(
            "SELECT policy_type, COUNT(*) FROM rules GROUP BY policy_type ORDER BY policy_type"
        ).fetchall()
        assert types == [
            ("bypass", 1),
            ("egress_ip", 1),
            ("enterprise_browser", 1),
            ("rtp", 3),
        ]

        rtp = conn.execute(
            """
            SELECT id, action, inspect_json, scan_fallback
            FROM rules WHERE policy_type='rtp' AND id='2'
            """
        ).fetchone()
        assert rtp[1] == "ALLOW"
        assert json.loads(rtp[2]) == {"dlp": True}
        assert rtp[3] == "fallback_block"

        bypass = conn.execute(
            "SELECT ssl_mode, action FROM rules WHERE policy_type='bypass'"
        ).fetchone()
        assert bypass == ("dnd", "BYPASS")
    finally:
        conn.close()


def test_store_legacy_policy_compiles_v2_schema(tmp_path):
    stored = store_policy(tmp_path, 9, LEGACY_POLICY)
    verify_sqlite_schema(stored.db_path)

    conn = sqlite3.connect(stored.db_path)
    try:
        row = conn.execute(
            "SELECT policy_type, action FROM rules WHERE id='1'"
        ).fetchone()
        assert row == ("rtp", "BLOCK")
    finally:
        conn.close()


def test_api_upload_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setenv("ZTFP_POLICY_DIR", str(tmp_path))
    monkeypatch.setenv("CONTROL_PLANE_API_TOKEN", "test-token")

    from api.server import app

    client = app.test_client()
    resp = client.post(
        "/api/v1/tenants/2/policy",
        json=MULTI_BLOCK_POLICY,
        headers={"Authorization": "Bearer test-token"},
    )
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["tenant_id"] == 2
    assert body["rule_count"] == 6
    assert Path(body["paths"]["db"]).exists()

    resp2 = client.post(
        "/api/v1/tenants/2/policy",
        json=MULTI_BLOCK_POLICY,
        headers={"Authorization": "Bearer wrong"},
    )
    assert resp2.status_code == 401


def test_local_compile_from_folder(tmp_path):
    workdir = tmp_path / "tenant-work"
    workdir.mkdir()
    json_path = workdir / "policy.json"
    json_path.write_text(json.dumps(MULTI_BLOCK_POLICY, indent=2), encoding="utf-8")

    from policy_compiler.local_compile import compile_policy_at

    result = compile_policy_at(workdir)
    assert result.db_path == workdir / "policy.db"
    assert result.meta_path == workdir / "policy.meta.json"
    verify_sqlite_schema(result.db_path)

    meta = json.loads(result.meta_path.read_text(encoding="utf-8"))
    assert meta["rule_count"] == 6
    assert meta["schema_version"] == "2"


def test_local_compile_cli(tmp_path):
    workdir = tmp_path / "cli-work"
    workdir.mkdir()
    json_path = workdir / "policy.json"
    json_path.write_text(json.dumps(LEGACY_POLICY, indent=2), encoding="utf-8")

    from policy_compiler.cli import main

    assert main([str(workdir)]) == 0
    assert (workdir / "policy.db").exists()
    verify_sqlite_schema(workdir / "policy.db")
