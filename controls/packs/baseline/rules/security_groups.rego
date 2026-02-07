package compliance

deny contains res if {
  rc := input.tfplan.resource_changes[_]
  rc.type == "aws_security_group"
  after := rc.change.after
  after != null

  ingress := after.ingress[_]
  cidr := ingress.cidr_blocks[_]
  cidr == "0.0.0.0/0"

  ingress.from_port <= 22
  ingress.to_port >= 22

  res := {
    "control_id": "SG-001",
    "severity": "high",
    "message": "Security group allows 0.0.0.0/0 on port 22",
    "address": rc.address,
    "resource_type": rc.type,
    "details": "ingress tcp includes 22",
    "fix_hint": "Restrict CIDRs or remove public SSH; use VPN/bastion.",
  }
}
