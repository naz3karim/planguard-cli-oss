package compliance

############################################
# Collect "after" objects (real + terraform_data fixtures)
############################################

s3_bucket_afters contains rec if {
  rc := input.tfplan.resource_changes[_]
  rc.type == "aws_s3_bucket"
  after := rc.change.after
  after != null
  rec := {"address": rc.address, "after": after}
}

s3_bucket_afters contains rec if {
  rc := input.tfplan.resource_changes[_]
  rc.type == "terraform_data"
  td := rc.change.after
  td != null
  td.input.type == "aws_s3_bucket"
  after := td.input.after
  after != null
  rec := {"address": rc.address, "after": after}
}

pab_afters contains rec if {
  rc := input.tfplan.resource_changes[_]
  rc.type == "aws_s3_bucket_public_access_block"
  after := rc.change.after
  after != null
  rec := {"address": rc.address, "after": after}
}

pab_afters contains rec if {
  rc := input.tfplan.resource_changes[_]
  rc.type == "terraform_data"
  td := rc.change.after
  td != null
  td.input.type == "aws_s3_bucket_public_access_block"
  after := td.input.after
  after != null
  rec := {"address": rc.address, "after": after}
}

############################################
# Controls
############################################

# S3-ENC-001: Require SSE on every S3 bucket in the plan/fixtures
deny contains res if {
  rec := s3_bucket_afters[_]
  after := rec.after

  not after.server_side_encryption_configuration

  res := {
    "control_id": "S3-ENC-001",
    "severity": "high",
    "message": "S3 bucket missing server-side encryption configuration",
    "address": rec.address,
    "resource_type": "aws_s3_bucket",
    "details": "server_side_encryption_configuration is missing",
    "fix_hint": "Enable SSE (SSE-S3 or SSE-KMS). Prefer KMS for sensitive buckets.",
  }
}

# S3PAB-001: At least one Public Access Block must exist (baseline expectation)
deny contains res if {
  count(pab_afters) == 0

  res := {
    "control_id": "S3PAB-001",
    "severity": "high",
    "message": "S3 Public Access Block is missing from this plan",
    "address": "N/A",
    "resource_type": "aws_s3_bucket_public_access_block",
    "details": "no aws_s3_bucket_public_access_block resources (or terraform_data fixtures) found",
    "fix_hint": "Add aws_s3_bucket_public_access_block with all 4 flags enabled.",
  }
}

# Helper: strict public access block (all 4 flags true)
is_strict_pab(a) if {
  a.block_public_acls == true
  a.block_public_policy == true
  a.ignore_public_acls == true
  a.restrict_public_buckets == true
}

# S3PAB-002: Every Public Access Block must set all 4 flags true
deny contains res if {
  rec := pab_afters[_]
  a := rec.after

  not is_strict_pab(a)

  res := {
    "control_id": "S3PAB-002",
    "severity": "high",
    "message": "S3 Public Access Block must enforce all 4 flags",
    "address": rec.address,
    "resource_type": "aws_s3_bucket_public_access_block",
    "details": sprintf(
      "expected all 4 true (got %v/%v/%v/%v)",
      [a.block_public_acls, a.block_public_policy, a.ignore_public_acls, a.restrict_public_buckets],
    ),
    "fix_hint": "Set block_public_acls=true, block_public_policy=true, ignore_public_acls=true, restrict_public_buckets=true.",
  }
}