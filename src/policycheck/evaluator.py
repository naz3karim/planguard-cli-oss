import json
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List

from policycheck.pack import Pack


def _opa_bin() -> str:
    return os.getenv("OPA_BIN", "opa")


def _run_opa_eval(rules_dir: Path, input_plan: Dict[str, Any], env: str) -> Dict[str, Any]:
    """
    OPA contract:
      Query: data.compliance
      Expected result value: {"deny": <set>, "warn": <set>} (sets become arrays in JSON)
    """
    with tempfile.TemporaryDirectory() as td:
        td_path = Path(td)
        input_path = td_path / "input.json"
        input_path.write_text(json.dumps({"tfplan": input_plan, "context": {"env": env}}), encoding="utf-8")

        cmd = [
            _opa_bin(),
            "eval",
            "--format=json",
            "-i",
            str(input_path),
            "-d",
            str(rules_dir),
            "data.compliance",
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True)

        if proc.returncode != 0:
            return {
                "errors": [{"message": "OPA eval failed", "stderr": proc.stderr.strip() or proc.stdout.strip()}],
                "deny": [],
                "warn": [],
            }

        parsed = json.loads(proc.stdout)
        value: Dict[str, Any] = {}
        try:
            value = parsed["result"][0]["expressions"][0].get("value", {}) or {}
        except Exception:
            value = {}

        deny = value.get("deny", []) or []
        warn = value.get("warn", []) or []

        # Sets come out as arrays in JSON; normalize anyway.
        if not isinstance(deny, list):
            deny = []
        if not isinstance(warn, list):
            warn = []

        return {"errors": [], "deny": deny, "warn": warn}


def evaluate(plan: Dict[str, Any], pack_dir: Path, env: str) -> Dict[str, Any]:
    try:
        pack = Pack.load(pack_dir)
    except Exception as e:
        return {
            "pack": {"name": pack_dir.name, "version": "unknown", "description": ""},
            "summary": {"denies": 0, "warnings": 0, "errors": 1},
            "denies": [],
            "warnings": [],
            "errors": [{"message": f"Failed to load pack: {e}"}],
        }

    if not pack.rules_dir.exists():
        return {
            "pack": {"name": pack.name, "version": pack.version, "description": pack.description},
            "summary": {"denies": 0, "warnings": 0, "errors": 1},
            "denies": [],
            "warnings": [],
            "errors": [{"message": f"rules_dir not found: {pack.rules_dir}"}],
        }

    out = _run_opa_eval(pack.rules_dir, plan, env)

    denies: List[Dict[str, Any]] = out["deny"]
    warns: List[Dict[str, Any]] = out["warn"]
    errors: List[Dict[str, Any]] = out["errors"]

    return {
        "pack": {"name": pack.name, "version": pack.version, "description": pack.description},
        "summary": {"denies": len(denies), "warnings": len(warns), "errors": len(errors)},
        "denies": denies,
        "warnings": warns,
        "errors": errors,
    }