"""REST API for tenant policy upload (control plane)."""

from __future__ import annotations

import os
from pathlib import Path

from flask import Flask, jsonify, request

from policy_compiler.storage import store_policy
from policy_compiler.validator import PolicyValidationError, validate_policy_document

app = Flask(__name__)


def policy_root() -> Path:
    return Path(os.environ.get("ZTFP_POLICY_DIR", "/var/ztfp/policies/"))


def api_token() -> str:
    return os.environ.get("CONTROL_PLANE_API_TOKEN", "")


def authorize() -> bool:
    token = api_token()
    if token == "":
        return True
    auth = request.headers.get("Authorization", "")
    if not auth.lower().startswith("bearer "):
        return False
    return auth[7:].strip() == token


@app.get("/healthz")
def healthz():
    return jsonify({"status": "ok"}), 200


@app.post("/api/v1/tenants/<int:tenant_id>/policy")
def upload_policy(tenant_id: int):
    if not authorize():
        return jsonify({"error": "unauthorized"}), 401

    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 400

    doc = request.get_json(silent=False)
    try:
        validate_policy_document(doc)
        stored = store_policy(policy_root(), tenant_id, doc)
    except PolicyValidationError as exc:
        return jsonify({"error": str(exc)}), 400
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    return (
        jsonify(
            {
                "tenant_id": stored.tenant_id,
                "version": stored.version,
                "rule_count": stored.rule_count,
                "checksum": stored.checksum,
                "compiled_at": stored.compiled_at,
                "paths": {
                    "json": str(stored.json_path),
                    "db": str(stored.db_path),
                    "meta": str(stored.meta_path),
                },
            }
        ),
        200,
    )


def main() -> None:
    host = os.environ.get("CONTROL_PLANE_HOST", "127.0.0.1")
    port = int(os.environ.get("CONTROL_PLANE_PORT", "8090"))
    app.run(host=host, port=port)


if __name__ == "__main__":
    main()
