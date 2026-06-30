"""Persist tenant policy artifacts with atomic DB swap."""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from policy_compiler.compiler import SCHEMA_VERSION, compile_policy_to_sqlite, verify_sqlite_schema
from policy_compiler.normalizer import count_rules
from policy_compiler.validator import validate_policy_document


@dataclass
class StoredPolicy:
    tenant_id: int
    version: int
    rule_count: int
    checksum: str
    compiled_at: str
    json_path: Path
    db_path: Path
    meta_path: Path


def tenant_dir(policy_root: Path, tenant_id: int) -> Path:
    return policy_root / str(tenant_id)


def next_version(meta_path: Path) -> int:
    if not meta_path.exists():
        return 1
    with meta_path.open(encoding="utf-8") as f:
        meta = json.load(f)
    return int(meta.get("version", 0)) + 1


def store_policy(
    policy_root: Path,
    tenant_id: int,
    doc: dict[str, Any],
) -> StoredPolicy:
    if tenant_id <= 0:
        raise ValueError("tenant_id must be a positive integer")

    doc = validate_policy_document(doc)

    tdir = tenant_dir(policy_root, tenant_id)
    tdir.mkdir(parents=True, exist_ok=True)

    json_path = tdir / "policy.json"
    db_path = tdir / "policy.db"
    db_tmp = tdir / "policy.db.tmp"
    meta_path = tdir / "policy.meta.json"

    canonical = json.dumps(doc, indent=2, ensure_ascii=False) + "\n"
    checksum = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    rule_count = count_rules(doc)
    version = next_version(meta_path)
    compiled_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    json_path.write_text(canonical, encoding="utf-8")

    if db_tmp.exists():
        db_tmp.unlink()
    compile_policy_to_sqlite(doc, db_tmp)
    verify_sqlite_schema(db_tmp)
    os.replace(db_tmp, db_path)

    meta = {
        "tenant_id": tenant_id,
        "version": version,
        "rule_count": rule_count,
        "checksum": checksum,
        "compiled_at": compiled_at,
        "schema_version": SCHEMA_VERSION,
        "evaluation_order": ["bypass", "egress_ip", "enterprise_browser", "rtp"],
    }
    meta_path.write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")

    return StoredPolicy(
        tenant_id=tenant_id,
        version=version,
        rule_count=rule_count,
        checksum=checksum,
        compiled_at=compiled_at,
        json_path=json_path,
        db_path=db_path,
        meta_path=meta_path,
    )
