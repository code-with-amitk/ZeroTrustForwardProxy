"""Normalize tenant policy documents to the canonical multi-block envelope."""

from __future__ import annotations

from copy import deepcopy
from typing import Any

TERMINAL_ACTIONS = frozenset({"ALLOW", "BLOCK", "BYPASS", "FWD", "COACH", "CONTINUE"})
SCAN_FALLBACKS = frozenset({"fallback_allow", "fallback_alert", "fallback_block"})
POLICY_TYPES = ("rtp", "bypass", "egress_ip", "enterprise_browser")

_LEGACY_ACTION_MAP = {
    "allow": "ALLOW",
    "block": "BLOCK",
    "coach": "COACH",
    "bypass": "BYPASS",
    "fwd": "FWD",
    "forward": "FWD",
    "continue": "CONTINUE",
}


def normalize_terminal_action(action: str) -> str:
    upper = action.upper()
    if upper in TERMINAL_ACTIONS:
        return upper
    mapped = _LEGACY_ACTION_MAP.get(action.lower())
    if mapped:
        return mapped
    return upper


def _migrate_legacy_rule(rule: dict[str, Any]) -> dict[str, Any]:
    """Map flat baseline rules with inspect_* actions into RTP rules."""
    migrated = deepcopy(rule)
    raw_action = rule.get("action", "ALLOW")
    lower = raw_action.lower()

    inspect: dict[str, Any] = {}
    if lower == "inspect_dlp":
        inspect["dlp"] = True
        migrated["action"] = "ALLOW"
        migrated.setdefault("scan_fallback", "fallback_block")
    elif lower == "inspect_mcp":
        mcp = rule.get("mcp") or {}
        inspect["mcp"] = mcp if mcp else True
        migrated["action"] = "ALLOW"
        migrated.setdefault("scan_fallback", "fallback_block")
    else:
        migrated["action"] = normalize_terminal_action(raw_action)

    if inspect:
        migrated["inspect"] = inspect
    migrated.pop("mcp", None)
    return migrated


def normalize_policy_document(doc: dict[str, Any]) -> dict[str, Any]:
    """Return canonical envelope: default_action + policies.{rtp,bypass,...}."""
    if "policies" in doc:
        normalized = deepcopy(doc)
        normalized["default_action"] = normalize_terminal_action(
            doc.get("default_action", "ALLOW")
        )
        policies = normalized.setdefault("policies", {})
        for policy_type in POLICY_TYPES:
            block = policies.get(policy_type)
            if not block:
                continue
            rules = block.get("rules") or []
            for rule in rules:
                if "action" in rule:
                    rule["action"] = normalize_terminal_action(rule["action"])
        return normalized

    # Legacy flat document: rules[] at top level → policies.rtp.rules[]
    rtp_rules = [_migrate_legacy_rule(rule) for rule in doc.get("rules", [])]
    return {
        "default_action": normalize_terminal_action(doc.get("default_action", "ALLOW")),
        "policies": {
            "rtp": {"rules": rtp_rules},
        },
    }


def iter_policy_rules(doc: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    """Yield (policy_type, rule) pairs from a normalized document."""
    policies = doc.get("policies") or {}
    out: list[tuple[str, dict[str, Any]]] = []
    for policy_type in POLICY_TYPES:
        block = policies.get(policy_type) or {}
        for rule in block.get("rules") or []:
            out.append((policy_type, rule))
    return out


def count_rules(doc: dict[str, Any]) -> int:
    return len(iter_policy_rules(doc))
