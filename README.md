# PolicyCheck

PolicyCheck is a Terraform compliance-as-code gate built on OPA 1.x (Rego v1).  
It evaluates `terraform plan -json` output and fails CI/CD pipelines when policy violations are detected.

CLI-first. Docker-first. No SaaS dependency.

---

WHAT YOU GET

- Working policy engine using OPA 1.13.x + Rego v1
- Deterministic CI-safe exit codes:
  - 0 = pass
  - 1 = policy denies (fail build)
  - 2 = engine / config error
- Built-in policy packs:
  - baseline (low-noise baseline controls)
  - soc2-prod (baseline + SOC 2 production controls)
- Fully containerized Docker distribution containing:
  - PolicyCheck CLI
  - OPA binary
  - Built-in policy packs
- Designed for CI/CD usage

---

REQUIREMENTS

- Terraform
- Docker (recommended)
- OR Python 3.11+ for local CLI usage

---

QUICK START (DOCKER – RECOMMENDED)

1) Generate Terraform plan JSON

terraform plan -out=tfplan  
terraform show -json tfplan > plan.json

2) Run PolicyCheck

docker run --rm -v "$PWD:/work" -w /work ghcr.io/<ORG>/policycheck:0.2.0 plan.json --pack baseline --env prod

If policy violations exist, the container exits with code 1 and fails the build.

---

LOCAL CLI USAGE

policycheck plan.json --pack baseline --env prod

Flags:
--pack     Policy pack name or path (default: baseline)
--env      Environment label (prod/dev)
--format   markdown | json
--out      Output file path or '-' for stdout
--version  Print version

---

CI/CD INTEGRATION EXAMPLES

GitHub Actions:

terraform plan -out=tfplan  
terraform show -json tfplan > plan.json  
docker run --rm -v "$PWD:/work" -w /work ghcr.io/<ORG>/policycheck:0.2.0 plan.json --pack baseline --env prod

GitLab CI:

terraform plan -out=tfplan  
terraform show -json tfplan > plan.json  
docker run --rm -v "$PWD:/work" -w /work ghcr.io/<ORG>/policycheck:0.2.0 plan.json --pack baseline --env prod

Jenkins:

terraform plan -out=tfplan  
terraform show -json tfplan > plan.json  
docker run --rm -v "$PWD:/work" -w /work ghcr.io/<ORG>/policycheck:0.2.0 plan.json --pack baseline --env prod

---

REPOSITORY STRUCTURE

Dockerfile  
pyproject.toml  
src/policycheck/  
controls/packs/baseline/  
controls/packs/soc2-prod/  

---

WHAT THIS IS NOT

- No SaaS lock-in
- No API keys
- No central service dependency

PolicyCheck fails bad Terraform plans locally, predictably, and early.



## CI/CD Examples (Optional)

PolicyCheck runs anywhere Docker runs.  
Below are copy-paste examples for common CI systems.  
All examples execute the **same Docker command** and rely on exit codes to gate builds.

---

### GitHub Actions, GitLab CI, Jenkins

```text
GITHUB ACTIONS (.github/workflows/terraform.yml)

- name: Terraform Compliance
  run: |
    terraform plan -out=tfplan
    terraform show -json tfplan > plan.json
    docker run --rm \
      -v "$PWD:/work" \
      -w /work \
      ghcr.io/<ORG>/policycheck:0.2.0 \
      plan.json --pack baseline --env prod


GITLAB CI (.gitlab-ci.yml)

policycheck:
  stage: test
  script:
    - terraform plan -out=tfplan
    - terraform show -json tfplan > plan.json
    - docker run --rm \
        -v "$PWD:/work" \
        -w /work \
        ghcr.io/<ORG>/policycheck:0.2.0 \
        plan.json --pack baseline --env prod


JENKINS (Declarative Pipeline)

stage('Terraform Compliance') {
  steps {
    sh '''
      terraform plan -out=tfplan
      terraform show -json tfplan > plan.json
      docker run --rm \
        -v "$PWD:/work" \
        -w /work \
        ghcr.io/<ORG>/policycheck:0.2.0 \
        plan.json --pack baseline --env prod
    '''
  }
}