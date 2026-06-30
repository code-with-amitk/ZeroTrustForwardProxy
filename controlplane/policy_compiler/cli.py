"""CLI: compile policy.json to policy.db in the same folder."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from policy_compiler.local_compile import compile_policy_at
from policy_compiler.validator import PolicyValidationError


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Validate policy.json and compile it to policy.db in the same folder. "
            "Use this for offline testing before copying the .db to "
            "/var/ztfp/policies/{tenant_id}/."
        )
    )
    parser.add_argument(
        "path",
        type=Path,
        help="Path to policy.json or a folder containing policy.json",
    )
    parser.add_argument(
        "--no-meta",
        action="store_true",
        help="Do not write policy.meta.json",
    )
    parser.add_argument(
        "--rewrite-json",
        action="store_true",
        help="Rewrite policy.json with normalized canonical envelope",
    )
    parser.add_argument(
        "--db",
        type=Path,
        default=None,
        help="Override output policy.db path (default: beside policy.json)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result = compile_policy_at(
            args.path,
            db_path=args.db,
            write_meta=not args.no_meta,
            rewrite_json=args.rewrite_json,
        )
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except PolicyValidationError as exc:
        print(f"validation error: {exc}", file=sys.stderr)
        return 2
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(f"compiled {result.rule_count} rules")
    print(f"  json: {result.json_path}")
    print(f"  db:   {result.db_path}")
    if result.meta_path is not None:
        print(f"  meta: {result.meta_path}")
    print(f"  schema_version: {result.schema_version}")
    print()
    print("Copy to tenant policy store, e.g.:")
    print(f"  mkdir -p /var/ztfp/policies/1")
    print(f"  cp {result.json_path} {result.db_path} /var/ztfp/policies/1/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
