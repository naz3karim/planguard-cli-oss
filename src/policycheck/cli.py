import argparse
import json
import os
import sys
from pathlib import Path

from policycheck.evaluator import evaluate
from policycheck.report import render_markdown, render_json


def main() -> None:
    p = argparse.ArgumentParser(
        prog="policycheck",
        description="Terraform Compliance-as-Code gate (OPA/Rego). Fails on deny rules.",
    )
    p.add_argument("plan_json", help="Path to terraform plan JSON (terraform show -json tfplan)")
    p.add_argument(
        "--pack",
        default="controls/packs/baseline",
        help="Controls pack directory (e.g., controls/packs/soc2-prod)",
    )
    p.add_argument("--format", choices=["markdown", "json"], default="markdown")
    p.add_argument("--out", default="-", help="Output file path or '-' for stdout")
    p.add_argument("--env", default=os.getenv("POLICYCHECK_ENV", ""), help="Environment label (prod/dev)")
    args = p.parse_args()

    plan_path = Path(args.plan_json)
    if not plan_path.exists():
        print(f"ERROR: plan json not found: {plan_path}", file=sys.stderr)
        sys.exit(2)

    try:
        plan = json.loads(plan_path.read_text(encoding="utf-8"))
    except Exception as e:
        print(f"ERROR: failed to parse plan json: {e}", file=sys.stderr)
        sys.exit(2)

    result = evaluate(plan=plan, pack_dir=Path(args.pack), env=args.env)

    out_text = render_markdown(result) if args.format == "markdown" else render_json(result)

    if args.out == "-":
        print(out_text)
    else:
        Path(args.out).write_text(out_text, encoding="utf-8")

    if result["summary"]["errors"] > 0:
        sys.exit(2)
    if result["summary"]["denies"] > 0:
        sys.exit(1)
    sys.exit(0)
