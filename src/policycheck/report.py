# src/policycheck/report.py
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Tuple


Severity = str


_SEV_ORDER: Dict[Severity, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
    "unknown": 5,
}


def _now_utc_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _safe_str(v: Any, default: str = "") -> str:
    if v is None:
        return default
    try:
        s = str(v)
        return s if s else default
    except Exception:
        return default


def _norm_sev(sev: Any) -> Severity:
    s = _safe_str(sev, "unknown").strip().lower()
    return s if s else "unknown"


def _status(summary: Dict[str, Any]) -> str:
    # Priority: errors -> denies -> pass
    if int(summary.get("errors", 0) or 0) > 0:
        return "ERROR"
    if int(summary.get("denies", 0) or 0) > 0:
        return "FAIL"
    return "PASS"


def _emoji(status: str) -> str:
    return {"PASS": "✅", "FAIL": "❌", "ERROR": "⚠️"}.get(status, "ℹ️")


def _collect_findings(result: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]:
    denies = list(result.get("denies") or [])
    warnings = list(result.get("warnings") or [])
    errors = list(result.get("errors") or [])
    return denies, warnings, errors


def _dedupe(findings: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Dedupe by (control_id, address, message).
    Keeps first occurrence.
    """
    seen: set[Tuple[str, str, str]] = set()
    out: List[Dict[str, Any]] = []
    for f in findings:
        cid = _safe_str(f.get("control_id"), "UNKNOWN")
        addr = _safe_str(f.get("address"), "N/A")
        msg = _safe_str(f.get("message"), "")
        key = (cid, addr, msg)
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


def _sort_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    def key(f: Dict[str, Any]) -> Tuple[int, str, str]:
        sev = _norm_sev(f.get("severity"))
        return (_SEV_ORDER.get(sev, _SEV_ORDER["unknown"]), _safe_str(f.get("control_id"), ""), _safe_str(f.get("address"), ""))
    return sorted(findings, key=key)


def _count_by_severity(findings: Iterable[Dict[str, Any]]) -> Dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "unknown": 0}
    for f in findings:
        counts[_norm_sev(f.get("severity"))] = counts.get(_norm_sev(f.get("severity")), 0) + 1
    return counts


def _md_escape_inline(s: str) -> str:
    # Minimal inline escape
    return s.replace("`", "\\`")


def render_json(result: Dict[str, Any]) -> str:
    return json.dumps(result, indent=2, sort_keys=False)


def render_github(result: Dict[str, Any]) -> str:
    """
    GitHub Actions annotations.
    - Denies -> ::error
    - Warnings -> ::warning
    - Errors -> ::error (tooling errors)
    """
    denies, warnings, errors = _collect_findings(result)

    denies = _sort_findings(_dedupe(denies))
    warnings = _sort_findings(_dedupe(warnings))
    errors = _dedupe(errors)

    lines: List[str] = []

    # Tool errors (OPA failures, parsing issues, etc.)
    for e in errors:
        msg = _safe_str(e.get("message"), "PolicyCheck error")
        details = _safe_str(e.get("stderr") or e.get("details") or "", "")
        full = msg if not details else f"{msg} — {details}"
        # Keep it one line for Actions UI
        full = " ".join(full.splitlines()).strip()
        lines.append(f"::error title=POLICYCHECK ERROR::{full}")

    for f in warnings:
        cid = _safe_str(f.get("control_id"), "UNKNOWN")
        sev = _norm_sev(f.get("severity"))
        addr = _safe_str(f.get("address"), "N/A")
        msg = _safe_str(f.get("message"), "")
        details = _safe_str(f.get("details"), "")
        full = f"[{cid}] {msg} (severity={sev}, address={addr})"
        if details:
            full += f" — {details}"
        full = " ".join(full.splitlines()).strip()
        lines.append(f"::warning title=POLICYCHECK {cid}::{full}")

    for f in denies:
        cid = _safe_str(f.get("control_id"), "UNKNOWN")
        sev = _norm_sev(f.get("severity"))
        addr = _safe_str(f.get("address"), "N/A")
        msg = _safe_str(f.get("message"), "")
        details = _safe_str(f.get("details"), "")
        fix = _safe_str(f.get("fix_hint"), "")
        full = f"[{cid}] {msg} (severity={sev}, address={addr})"
        if details:
            full += f" — {details}"
        if fix:
            full += f" | fix: {fix}"
        full = " ".join(full.splitlines()).strip()
        lines.append(f"::error title=POLICYCHECK {cid}::{full}")

    return "\n".join(lines) + ("\n" if lines else "")


def render_markdown(result: Dict[str, Any]) -> str:
    denies, warnings, errors = _collect_findings(result)
    denies = _sort_findings(_dedupe(denies))
    warnings = _sort_findings(_dedupe(warnings))
    # errors are tool/runtime errors; render as-is but compact
    errors = _dedupe(errors)

    summary = result.get("summary") or {}
    pack = result.get("pack") or {}
    context = result.get("context") or {}

    status = _status(summary)
    stamp = _now_utc_iso()

    pack_name = _safe_str(pack.get("name"), _safe_str(result.get("pack_name"), ""))
    pack_ver = _safe_str(pack.get("version"), _safe_str(result.get("pack_version"), ""))
    pack_desc = _safe_str(pack.get("description"), _safe_str(result.get("pack_description"), ""))

    env = _safe_str((context.get("env") if isinstance(context, dict) else None) or result.get("env"), "")
    opa_ver = _safe_str(result.get("opa_version"), "")
    pc_ver = _safe_str(result.get("policycheck_version"), _safe_str(result.get("version"), ""))

    sev_counts_denies = _count_by_severity(denies)
    sev_counts_warn = _count_by_severity(warnings)

    lines: List[str] = []

    # Header
    title = f"PolicyCheck Report — {_emoji(status)} {status}"
    if pack_name:
        title += f" ({pack_name})"
    lines.append(f"# {title}\n")

    # Metadata
    meta_parts = []
    if pack_name:
        v = f" v{pack_ver}" if pack_ver else ""
        meta_parts.append(f"**Pack:** {pack_name}{v}")
    if pack_desc:
        meta_parts.append(f"**Description:** {pack_desc}")
    if env:
        meta_parts.append(f"**Env:** {env}")
    if pc_ver or opa_ver:
        ver_bits = []
        if pc_ver:
            ver_bits.append(f"PolicyCheck {pc_ver}")
        if opa_ver:
            ver_bits.append(f"OPA {opa_ver}")
        meta_parts.append(f"**Versions:** " + " • ".join(ver_bits))
    meta_parts.append(f"**Generated:** {stamp}")

    lines.append("\n".join(meta_parts))
    lines.append("")

    # Summary table (counts)
    denies_n = int(summary.get("denies", len(denies)) or 0)
    warns_n = int(summary.get("warnings", len(warnings)) or 0)
    errs_n = int(summary.get("errors", len(errors)) or 0)

    lines.append("## Summary")
    lines.append("| Result | Denies | Warnings | Errors | High | Medium | Low |")
    lines.append("|---|---:|---:|---:|---:|---:|---:|")
    lines.append(
        f"| {_emoji(status)} {status} | {denies_n} | {warns_n} | {errs_n} | "
        f"{sev_counts_denies.get('high', 0)} | {sev_counts_denies.get('medium', 0)} | {sev_counts_denies.get('low', 0)} |"
    )
    lines.append("")

    # Optional quick guidance
    if status == "FAIL" and denies:
        top = denies[0]
        lines.append("## Next steps (to unblock)")
        lines.append(f"- Fix **{_safe_str(top.get('control_id'), 'UNKNOWN')}**: {_safe_str(top.get('fix_hint'), _safe_str(top.get('message'), ''))}")
        if len(denies) > 1:
            lines.append(f"- Then address remaining denies (total: {len(denies)}).")
        lines.append("")

    # Errors section
    if errors:
        lines.append("## Errors")
        for e in errors:
            msg = _safe_str(e.get("message"), "OPA eval failed")
            stderr = e.get("stderr")
            details = _safe_str(stderr if stderr is not None else e.get("details"), "")
            lines.append(f"- **{_md_escape_inline(msg)}**")
            if details:
                lines.append(f"  - details: `{_md_escape_inline(' '.join(str(details).splitlines()))}`")
        lines.append("")

    # Warnings grouped by severity
    if warnings:
        lines.append("## Warnings")
        lines.extend(_render_grouped_findings_md(warnings))
        lines.append("")

    # Denies grouped by severity
    if denies:
        lines.append("## Denies")
        lines.extend(_render_grouped_findings_md(denies))
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def _render_grouped_findings_md(findings: List[Dict[str, Any]]) -> List[str]:
    """
    Group by severity then by control_id; each finding formatted like a ticket.
    """
    out: List[str] = []

    # Build groups
    groups: Dict[str, Dict[str, List[Dict[str, Any]]]] = {}
    for f in findings:
        sev = _norm_sev(f.get("severity"))
        cid = _safe_str(f.get("control_id"), "UNKNOWN")
        groups.setdefault(sev, {}).setdefault(cid, []).append(f)

    # Order severities
    sev_sorted = sorted(groups.keys(), key=lambda s: _SEV_ORDER.get(s, _SEV_ORDER["unknown"]))

    for sev in sev_sorted:
        out.append(f"### {sev.capitalize()}")
        cids = sorted(groups[sev].keys())
        for cid in cids:
            items = groups[sev][cid]
            # Sort addresses for stability
            items = sorted(items, key=lambda x: _safe_str(x.get("address"), ""))
            for f in items:
                msg = _safe_str(f.get("message"), "")
                addr = _safe_str(f.get("address"), "N/A")
                rtype = _safe_str(f.get("resource_type") or f.get("type"), "N/A")
                details = _safe_str(f.get("details"), "")
                fix = _safe_str(f.get("fix_hint"), "")

                out.append(f"- **{_md_escape_inline(cid)}**: {_md_escape_inline(msg)}")
                out.append(f"  - address: `{_md_escape_inline(addr)}`")
                out.append(f"  - type: `{_md_escape_inline(rtype)}`")
                if details:
                    out.append(f"  - details: `{_md_escape_inline(details)}`")
                if fix:
                    out.append(f"  - fix: {_md_escape_inline(fix)}")
        out.append("")

    return out