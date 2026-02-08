# syntax=docker/dockerfile:1
FROM python:3.11-slim

ARG OPA_VERSION=1.13.1

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates \
  && rm -rf /var/lib/apt/lists/* \
  && curl -L -o /usr/local/bin/opa \
    "https://github.com/open-policy-agent/opa/releases/download/v${OPA_VERSION}/opa_linux_amd64_static" \
  && chmod +x /usr/local/bin/opa \
  && opa version

WORKDIR /app

COPY pyproject.toml README.md /app/
COPY src/ /app/src/
COPY controls/ /app/controls/

RUN pip install -U pip && pip install .

ENTRYPOINT ["policycheck"]