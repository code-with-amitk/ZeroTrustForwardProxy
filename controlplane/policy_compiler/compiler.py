"""Compile validated policy JSON into SQLite."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from policy_compiler.normalizer import POLICY_TYPES, count_rules, iter_policy_rules

SCHEMA_VERSION = "2"

_CREATE_TABLES = """
CREATE TABLE IF NOT EXISTS policy_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS rules (
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
CREATE INDEX IF NOT EXISTS idx_rules_type_priority ON rules(policy_type, priority);
"""


def compile_policy_to_sqlite(doc: dict[str, Any], db_path: Path) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.executescript(_CREATE_TABLES)
        conn.execute("DELETE FROM policy_meta")
        conn.execute("DELETE FROM rules")

        conn.execute(
            "INSERT INTO policy_meta(key, value) VALUES (?, ?)",
            ("schema_version", SCHEMA_VERSION),
        )
        conn.execute(
            "INSERT INTO policy_meta(key, value) VALUES (?, ?)",
            ("default_action", doc.get("default_action", "ALLOW")),
        )
        conn.execute(
            "INSERT INTO policy_meta(key, value) VALUES (?, ?)",
            ("rule_count", str(count_rules(doc))),
        )
        conn.execute(
            "INSERT INTO policy_meta(key, value) VALUES (?, ?)",
            (
                "policy_types",
                json.dumps([pt for pt in POLICY_TYPES if doc.get("policies", {}).get(pt)]),
            ),
        )
        conn.execute(
            "INSERT INTO policy_meta(key, value) VALUES (?, ?)",
            (
                "evaluation_order",
                json.dumps(["bypass", "egress_ip", "enterprise_browser", "rtp"]),
            ),
        )

        for policy_type, rule in iter_policy_rules(doc):
            priority = int(rule.get("priority", 0))
            conditions = rule.get("conditions") or {}
            inspect = rule.get("inspect") or {}

            conn.execute(
                """
                INSERT INTO rules(
                    id, policy_type, priority, name, action, message,
                    conditions_json, inspect_json, scan_fallback,
                    ssl_mode, isolation
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    rule["id"],
                    policy_type,
                    priority,
                    rule.get("name", ""),
                    rule["action"],
                    rule.get("message", ""),
                    json.dumps(conditions),
                    json.dumps(inspect) if inspect else "",
                    rule.get("scan_fallback", ""),
                    rule.get("ssl_mode", ""),
                    rule.get("isolation", ""),
                ),
            )

        conn.commit()
    finally:
        conn.close()


def verify_sqlite_schema(db_path: Path) -> None:
    conn = sqlite3.connect(db_path)
    try:
        cur = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        )
        tables = {row[0] for row in cur.fetchall()}
        if "policy_meta" not in tables or "rules" not in tables:
            raise ValueError("compiled database missing required tables")

        version = conn.execute(
            "SELECT value FROM policy_meta WHERE key='schema_version'"
        ).fetchone()
        if not version or version[0] != SCHEMA_VERSION:
            raise ValueError("unsupported or missing schema_version in policy.db")

        cols = {
            row[1]
            for row in conn.execute("PRAGMA table_info(rules)").fetchall()
        }
        required = {
            "policy_type",
            "conditions_json",
            "inspect_json",
            "scan_fallback",
            "ssl_mode",
            "isolation",
        }
        missing = required - cols
        if missing:
            raise ValueError(f"rules table missing columns: {sorted(missing)}")
    finally:
        conn.close()
