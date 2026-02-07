package compliance

is_prod if { lower(input.context.env) == "prod" }

min_days := 365

deny contains res if {
  is_prod

  rc := input.tfplan.resource_changes[_]
  rc.type == "aws_cloudwatch_log_group"
  after := rc.change.after
  after != null

  not after.retention_in_days

  res := {
    "control_id": "LOG-RET-001",
    "severity": "medium",
    "message": "CloudWatch Log Group missing retention_in_days in prod",
    "address": rc.address,
    "resource_type": rc.type,
    "details": "retention_in_days not set",
    "fix_hint": sprintf("Set retention_in_days to >= %v.", [min_days]),
  }
}

deny contains res if {
  is_prod

  rc := input.tfplan.resource_changes[_]
  rc.type == "aws_cloudwatch_log_group"
  after := rc.change.after
  after != null

  after.retention_in_days < min_days

  res := {
    "control_id": "LOG-RET-002",
    "severity": "medium",
    "message": sprintf("CloudWatch Log Group retention too low in prod (min %v)", [min_days]),
    "address": rc.address,
    "resource_type": rc.type,
    "details": sprintf("retention_in_days=%v", [after.retention_in_days]),
    "fix_hint": sprintf("Increase retention_in_days to >= %v.", [min_days]),
  }
}