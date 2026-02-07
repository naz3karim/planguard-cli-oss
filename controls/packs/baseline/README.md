# policycheck (Terraform Compliance Gate)

A Compliance-as-Code gate for Terraform using OPA/Rego.

## Install
```bash
python3.11 -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -e .