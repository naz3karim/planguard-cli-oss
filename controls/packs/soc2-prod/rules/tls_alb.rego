package compliance

is_prod if { lower(input.context.env) == "prod" }

deny contains res if {
  is_prod

  rc := input.tfplan.resource_changes[_]
  rc.type == "aws_lb_listener"
  after := rc.change.after
  after != null

  upper(after.protocol) == "HTTP"

  res := {
    "control_id": "TLS-HTTP-001",
    "severity": "high",
    "message": "ALB listener uses HTTP in prod (must be HTTPS or redirect)",
    "address": rc.address,
    "resource_type": rc.type,
    "details": sprintf("protocol=%v port=%v", [after.protocol, after.port]),
    "fix_hint": "Use HTTPS listener with ACM cert + modern ssl_policy; optionally keep HTTP only as redirect.",
  }
}

deny contains res if {
  is_prod

  rc := input.tfplan.resource_changes[_]
  rc.type == "aws_lb_listener"
  after := rc.change.after
  after != null

  upper(after.protocol) == "HTTPS"
  not after.certificate_arn

  res := {
    "control_id": "TLS-CERT-001",
    "severity": "high",
    "message": "HTTPS listener missing certificate_arn",
    "address": rc.address,
    "resource_type": rc.type,
    "details": "certificate_arn not set",
    "fix_hint": "Attach an ACM certificate via certificate_arn.",
  }
}

deny contains res if {
  is_prod

  rc := input.tfplan.resource_changes[_]
  rc.type == "aws_lb_listener"
  after := rc.change.after
  after != null

  upper(after.protocol) == "HTTPS"
  not after.ssl_policy

  res := {
    "control_id": "TLS-POLICY-001",
    "severity": "medium",
    "message": "HTTPS listener missing ssl_policy (must enforce modern TLS)",
    "address": rc.address,
    "resource_type": rc.type,
    "details": "ssl_policy not set",
    "fix_hint": "Set a modern ssl_policy (TLS 1.2+ / TLS 1.3).",
  }
}