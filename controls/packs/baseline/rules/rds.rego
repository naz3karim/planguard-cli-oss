package compliance

deny contains res if {
  rc := input.tfplan.resource_changes[_]
  rc.type == "aws_db_instance"
  after := rc.change.after
  after != null

  after.storage_encrypted != true

  res := {
    "control_id": "RDS-ENC-001",
    "severity": "high",
    "message": "RDS instance must have storage_encrypted = true",
    "address": rc.address,
    "resource_type": rc.type,
    "details": "storage_encrypted is false or missing",
    "fix_hint": "Set storage_encrypted=true (and use KMS key for sensitive data).",
  }
}

deny contains res if {
  rc := input.tfplan.resource_changes[_]
  rc.type == "aws_db_instance"
  after := rc.change.after
  after != null

  after.publicly_accessible == true

  res := {
    "control_id": "RDS-PUBLIC-001",
    "severity": "high",
    "message": "RDS instance must not be publicly accessible",
    "address": rc.address,
    "resource_type": rc.type,
    "details": "publicly_accessible=true",
    "fix_hint": "Set publicly_accessible=false and place DB in private subnets.",
  }
}