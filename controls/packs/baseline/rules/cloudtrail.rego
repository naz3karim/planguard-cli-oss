package compliance

has_cloudtrail if {
  some rc in input.tfplan.resource_changes
  rc.type == "aws_cloudtrail"
  after := rc.change.after
  after != null
  after.is_multi_region_trail == true
  after.enable_log_file_validation == true
}

deny contains res if {
  not has_cloudtrail

  res := {
    "control_id": "CLOUDTRAIL-001",
    "severity": "medium",
    "message": "CloudTrail missing (multi-region + log file validation) in this plan",
    "address": "N/A",
    "resource_type": "aws_cloudtrail",
    "details": "expected aws_cloudtrail is_multi_region_trail=true and enable_log_file_validation=true",
    "fix_hint": "Provision CloudTrail with multi-region + log file validation; store logs securely and retain.",
  }
}