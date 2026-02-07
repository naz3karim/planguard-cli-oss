package compliance

# Demo-grade heuristic: checks for Action="*" and Resource="*" in inline user policy string.
# Replace with proper JSON parsing later.

deny contains res if {
  rc := input.tfplan.resource_changes[_]
  rc.type == "aws_iam_user_policy"
  after := rc.change.after
  after != null
  policy := after.policy
  policy != null

  contains(policy, "\"Action\":\"*\"")
  contains(policy, "\"Resource\":\"*\"")

  res := {
    "control_id": "IAM-WILDCARD-001",
    "severity": "high",
    "message": "IAM user inline policy appears to grant wildcard admin privileges",
    "address": rc.address,
    "resource_type": rc.type,
    "details": "Action=* and Resource=* detected in policy JSON string",
    "fix_hint": "Use least-privilege roles; avoid inline user policies; restrict actions/resources.",
  }
}