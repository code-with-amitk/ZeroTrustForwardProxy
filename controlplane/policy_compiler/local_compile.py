"""Compile policy.json to policy.db in a local folder (offline / Go testing)."""

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
from policy_compiler.validator import PolicyValidationError, validate_policy_document

DEFAULT_JSON_NAME = "policy.json"
DEFAULT_DB_NAME = "policy.db"
DEFAULT_META_NAME = "policy.meta.json"


@dataclass
class CompiledPolicyFile:
    json_path: Path
    db_path: Path
    meta_path: Path | None
    rule_count: int
    checksum: str
    compiled_at: str
    schema_version: str


def resolve_policy_json(path: Path) -> Path:
    """Return path to policy.json from a file or directory argument."""
    path = path.resolve()
    if path.is_dir():
        candidate = path / DEFAULT_JSON_NAME
        if not candidate.is_file():
            raise FileNotFoundError(f"{DEFAULT_JSON_NAME} not found in {path}")
        return candidate
    if path.is_file():
        return path
    raise FileNotFoundError(f"policy path not found: {path}")


def compile_policy_file(
    json_path: Path,
    *,
    db_path: Path | None = None,
    write_meta: bool = True,
    rewrite_json: bool = False,
) -> CompiledPolicyFile:
    """Validate JSON and write policy.db beside the source file."""
    json_path = json_path.resolve()
    if not json_path.is_file():
        raise FileNotFoundError(f"policy JSON not found: {json_path}")

    raw = json.loads(json_path.read_text(encoding="utf-8"))
    doc = validate_policy_document(raw)

    out_dir = json_path.parent
    db_path = (db_path or out_dir / DEFAULT_DB_NAME).resolve()
    meta_path = out_dir / DEFAULT_META_NAME if write_meta else None
    db_tmp = db_path.with_suffix(db_path.suffix + ".tmp")

    canonical = json.dumps(doc, indent=2, ensure_ascii=False) + "\n"
    checksum = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    rule_count = count_rules(doc)
    compiled_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    if rewrite_json:
        json_path.write_text(canonical, encoding="utf-8")

    if db_tmp.exists():
        db_tmp.unlink()
    compile_policy_to_sqlite(doc, db_tmp)
    verify_sqlite_schema(db_tmp)
    os.replace(db_tmp, db_path)

    if meta_path is not None:
        meta = {
            "rule_count": rule_count,
            "checksum": checksum,
            "compiled_at": compiled_at,
            "schema_version": SCHEMA_VERSION,
            "evaluation_order": ["bypass", "egress_ip", "enterprise_browser", "rtp"],
            "source_json": str(json_path),
        }
        tenant_id = doc.get("tenant_id")
        if tenant_id is not None:
            meta["tenant_id"] = tenant_id
        meta_path.write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")

    return CompiledPolicyFile(
        json_path=json_path,
        db_path=db_path,
        meta_path=meta_path,
        rule_count=rule_count,
        checksum=checksum,
        compiled_at=compiled_at,
        schema_version=SCHEMA_VERSION,
    )


def compile_policy_at(path: Path, **kwargs: Any) -> CompiledPolicyFile:
    """Compile from a directory (policy.json inside) or direct JSON file path."""
    return compile_policy_file(resolve_policy_json(path), **kwargs)
