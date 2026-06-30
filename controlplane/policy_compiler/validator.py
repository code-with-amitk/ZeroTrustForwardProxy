"""JSON Schema and business-rule validation for tenant policies."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import jsonschema

from policy_compiler.normalizer import (
    POLICY_TYPES,
    count_rules,
    iter_policy_rules,
    normalize_policy_document,
)

SCHEMA_PATH = Path(__file__).resolve().parent.parent / "schema" / "policy.schema.json"
MAX_RULES_DEFAULT = 5000
MAX_POLICY_BYTES_DEFAULT = 5 * 1024 * 1024


class PolicyValidationError(Exception):
    """Raised when policy JSON fails schema or business validation."""


def load_schema() -> dict[str, Any]:
    with SCHEMA_PATH.open(encoding="utf-8") as f:
        return json.load(f)


def _validate_regex_patterns(
    rule_id: str,
    policy_type: str,
    field: str,
    patterns: list[str],
) -> None:
    for pattern in patterns:
        try:
            re.compile(pattern)
        except re.error as exc:
            raise PolicyValidationError(
                f"rule {rule_id} ({policy_type}) {field} pattern {pattern!r} invalid: {exc}"
            ) from exc


def _validate_rule_business(policy_type: str, rule: dict[str, Any]) -> None:
    rule_id = rule["id"]
    conditions = rule.get("conditions") or {}

    for field in ("domains", "destinations"):
        patterns = conditions.get(field) or []
        if patterns:
            _validate_regex_patterns(rule_id, policy_type, field, patterns)

    if policy_type == "rtp":
        inspect = rule.get("inspect") or {}
        mcp = inspect.get("mcp")
        if isinstance(mcp, dict):
            for pattern in mcp.get("tool_names") or []:
                _validate_regex_patterns(rule_id, policy_type, "mcp.tool_names", [pattern])

        if inspect and not rule.get("scan_fallback"):
            # Default is applied at compile time; warn only if inspect without fallback?
            pass

    if "priority" in rule and not isinstance(rule["priority"], int):
        raise PolicyValidationError(f"rule {rule_id} ({policy_type}) priority must be integer")


def validate_policy_document(
    doc: dict[str, Any],
    *,
    max_rules: int = MAX_RULES_DEFAULT,
    max_bytes: int = MAX_POLICY_BYTES_DEFAULT,
    normalize: bool = True,
) -> dict[str, Any]:
    """Validate policy JSON. Returns normalized canonical document when normalize=True."""
    if normalize:
        doc = normalize_policy_document(doc)

    raw = json.dumps(doc, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    if len(raw) > max_bytes:
        raise PolicyValidationError(f"policy document exceeds max size ({max_bytes} bytes)")

    schema = load_schema()
    try:
        jsonschema.validate(instance=doc, schema=schema)
    except jsonschema.ValidationError as exc:
        raise PolicyValidationError(str(exc.message)) from exc

    total = count_rules(doc)
    if total > max_rules:
        raise PolicyValidationError(f"rule count {total} exceeds max {max_rules}")

    if total == 0:
        raise PolicyValidationError("policy must contain at least one rule across policy blocks")

    seen_ids: set[str] = set()
    for policy_type, rule in iter_policy_rules(doc):
        rule_id = rule["id"]
        key = f"{policy_type}:{rule_id}"
        if key in seen_ids:
            raise PolicyValidationError(f"duplicate rule id in {policy_type}: {rule_id}")
        seen_ids.add(key)
        _validate_rule_business(policy_type, rule)

    policies = doc.get("policies") or {}
    for policy_type in POLICY_TYPES:
        if policy_type not in policies:
            continue
        if not isinstance(policies[policy_type], dict):
            raise PolicyValidationError(f"policies.{policy_type} must be an object")

    return doc
