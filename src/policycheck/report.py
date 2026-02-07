import json
from datetime import datetime, timezone
from typing import Any, Dict


def render_json(result: Dict[str, Any]) -> str:
    payload = dict(result)
    payload["generated_at"] = datetime.now(timezone.utc).isoformat()
    return json.dumps(payload, indent=2)


def render_markdown(result: Dict[str, Any]) -> str:
    s = result["summary"]
    pack = result["pack"]
    lines = []
    lines.append("# Terraform Compliance Report")
    lines.append("")
    lines.append(f"- Pack: **{pack.get('name','')}** v{pack.get('version','')}")
    if pack.get("description"):
        lines.append(f"- Description: {pack['description']}")
    lines.append(f"- Denies: **{s['denies']}**")
    lines.append(f"- Warnings: **{s['warnings']}**")
    lines.append(f"- Errors: **{s['errors']}**")
    lines.append("")

    if result.get("errors"):
        lines.append("## Errors")
        for e in result["errors"]:
            lines.append(f"- {e.get('message','error')}")
            if e.get("stderr"):
                lines.append(f"  - stderr: `{e['stderr']}`")
        lines.append("")

    if result.get("denies"):
        lines.append("## Denies")
        for d in result["denies"]:
            cid = d.get("control_id", "UNKNOWN")
            sev = d.get("severity", "high")
            msg = d.get("message", "")
            addr = d.get("address", "")
            fix = d.get("fix_hint", "")
            lines.append(f"- **{cid}** ({sev}): {msg}")
            if addr:
                lines.append(f"  - address: `{addr}`")
            if d.get("resource_type"):
                lines.append(f"  - type: `{d['resource_type']}`")
            if d.get("details"):
                lines.append(f"  - details: `{d['details']}`")
            if fix:
                lines.append(f"  - fix: {fix}")
        lines.append("")

    return "\n".join(lines)
