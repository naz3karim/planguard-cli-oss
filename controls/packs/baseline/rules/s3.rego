package compliance

deny contains res if {
  rc := input.tfplan.resource_changes[_]
  rc.type == "aws_s3_bucket"
  after := rc.change.after
  after != null

  not after.server_side_encryption_configuration

  res := {
    "control_id": "S3-ENC-001",
    "severity": "high",
    "message": "S3 bucket missing server-side encryption configuration",
    "address": rc.address,
    "resource_type": rc.type,
    "details": "server_side_encryption_configuration is missing",
    "fix_hint": "Enable SSE (SSE-S3 or SSE-KMS). Prefer KMS for sensitive buckets.",
  }
}