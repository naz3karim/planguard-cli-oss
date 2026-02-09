package compliance

# Collect aws_cloudtrail "after" objects from either:
#   (A) real Terraform resources (aws_cloudtrail)
#   (B) terraform_data fixtures (input.type == aws_cloudtrail)
cloudtrail_afters contains rec if {
  rc := input.tfplan.resource_changes[_]
  rc.type == "aws_cloudtrail"
  after := rc.change.after
  after != null
  rec := {"address": rc.address, "after": after}
}

cloudtrail_afters contains rec if {
  rc := input.tfplan.resource_changes[_]
  rc.type == "terraform_data"
  td := rc.change.after
  td != null
  td.input.type == "aws_cloudtrail"
  after := td.input.after
  after != null
  rec := {"address": rc.address, "after": after}
}

has_good_cloudtrail if {
  some rec in cloudtrail_afters
  a := rec.after
  a.is_multi_region_trail == true
  a.enable_log_file_validation == true
}

deny contains res if {
  not has_good_cloudtrail

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