# src/policycheck/cli.py
import argparse
import json
import os
import sys
from pathlib import Path
from importlib.metadata import version as pkg_version

from policycheck.evaluator import evaluate
from policycheck.report import (
    render_markdown,
    render_json,
    render_github,
)


def _resolve_pack(pack_arg: str) -> Path:
    """
    Resolve a policy pack.
    - Absolute or relative path → use directly
    - Otherwise → controls/packs/<name>
    """
    if pack_arg.startswith(("/", "./", "../")):
        return Path(pack_arg)
    return Path("controls") / "packs" / pack_arg


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="policycheck",
        description=(
            "PolicyCheck — CI-native Infrastructure Compliance Gate.\n"
            "Evaluates Terraform plans against compliance policy packs "
            "(OPA/Rego) and fails builds on violations."
        ),
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {pkg_version('policycheck')}",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # -------------------------
    # check command
    # -------------------------
    check = subparsers.add_parser(
        "check",
        help="Evaluate a Terraform plan JSON against a policy pack",
    )

    check.add_argument(
        "plan_json",
        help="Path to Terraform plan JSON (terraform show -json tfplan)",
    )

    check.add_argument(
        "--pack",
        default="baseline",
        help="Policy pack name (baseline, soc2-prod) or path to a pack directory",
    )

    check.add_argument(
        "--format",
        choices=["markdown", "json", "github"],
        default="markdown",
        help="Output format (default: markdown)",
    )

    check.add_argument(
        "--out",
        default="-",
        help="Output file path or '-' for stdout",
    )

    check.add_argument(
        "--env",
        default=os.getenv("POLICYCHECK_ENV", ""),
        help="Environment label (e.g. prod, staging, dev)",
    )

    args = parser.parse_args()

    if args.command != "check":
        parser.error("Unknown command")

    # -------------------------
    # Load Terraform plan
    # -------------------------
    plan_path = Path(args.plan_json)
    if not plan_path.exists():
        print(f"ERROR: Terraform plan JSON not found: {plan_path}", file=sys.stderr)
        sys.exit(2)

    try:
        plan = json.loads(plan_path.read_text(encoding="utf-8"))
    except Exception as e:
        print(f"ERROR: Failed to parse Terraform plan JSON: {e}", file=sys.stderr)
        sys.exit(2)

    # -------------------------
    # Resolve policy pack
    # -------------------------
    pack_dir = _resolve_pack(args.pack)
    if not pack_dir.exists():
        print(
            f"ERROR: Policy pack not found: {pack_dir} (arg was: {args.pack})",
            file=sys.stderr,
        )
        sys.exit(2)

    # -------------------------
    # Evaluate
    # -------------------------
    result = evaluate(
        plan=plan,
        pack_dir=pack_dir,
        env=args.env,
    )

    # -------------------------
    # Render output
    # -------------------------
    if args.format == "markdown":
        output = render_markdown(result)
    elif args.format == "json":
        output = render_json(result)
    elif args.format == "github":
        output = render_github(result)
    else:
        print(f"ERROR: Unknown format: {args.format}", file=sys.stderr)
        sys.exit(2)

    # -------------------------
    # Write output
    # -------------------------
    if args.out == "-":
        print(output)
    else:
        Path(args.out).write_text(output, encoding="utf-8")

    # -------------------------
    # Exit code contract (CI-safe)
    # -------------------------
    # 0 = pass
    # 1 = policy denies (compliance failure)
    # 2 = tool / evaluation error
    summary = result.get("summary", {})
    if summary.get("errors", 0) > 0:
        sys.exit(2)
    if summary.get("denies", 0) > 0:
        sys.exit(1)

    sys.exit(0)