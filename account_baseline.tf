# --- EBS encryption by default ---------------------------------------------

# Any EBS volume created in these regions from now on is encrypted, including
# ones created by people clicking through the console. Uses the AWS-managed
# aws/ebs key unless a custom default is set separately.
#
# The setting is per-region, so it needs one instance per region the account
# operates in. AWS provider v6 accepts `region` on the resource itself, which
# is what lets this be a for_each over a list rather than one aliased provider
# block per region and a copy of this resource for each.
resource "aws_ebs_encryption_by_default" "this" {
  for_each = toset(local.operating_regions)

  region  = each.value
  enabled = true
}

# --- Instance metadata defaults (IMDSv2) -----------------------------------

# Forces IMDSv2 on every EC2 instance launched from now on, including ones
# created by people clicking through the console. IMDSv1 answers an
# unauthenticated GET, so any server-side request forgery in anything running
# on an instance reads that instance's role credentials straight out of the
# metadata service. IMDSv2 requires a PUT to get a token first, which SSRF
# generally cannot produce.
#
# This is the account default, not a constraint: a launch that explicitly asks
# for `optional` still gets it. It removes the failure mode where nobody set
# the field at all, which is the one that actually happens.
#
# hop_limit is 2, not 1. The hop limit is a TTL on the metadata response, and
# 1 means "the instance itself only" -- which blocks containers, because a
# container's packet has already crossed the bridge to get out. ECS on EC2 and
# EKS both need 2. Setting 1 here would look stricter and would break every
# containerised workload the account is likely to run.
#
# Per-region like the settings above, so it gets the same for_each.
resource "aws_ec2_instance_metadata_defaults" "this" {
  for_each = toset(local.operating_regions)

  region                      = each.value
  http_tokens                 = "required"
  http_endpoint               = "enabled"
  http_put_response_hop_limit = 2
}

# --- IAM Access Analyzer ---------------------------------------------------

# Flags resource policies that grant access outside the account. Free, and
# pointed straight at what this project builds: the KMS key policies and bucket
# policies here are exactly the kind of thing it evaluates, including the
# `"AWS": ["*"]` principals that are safe only because of their conditions.
#
# Regional like EBS encryption -- an analyzer only sees resources in its own
# region -- so it gets the same for_each.
resource "aws_accessanalyzer_analyzer" "account" {
  for_each = toset(local.operating_regions)

  region        = each.value
  analyzer_name = "account-external-access"
  type          = "ACCOUNT"
}

# --- Account alias ---------------------------------------------------------

# Puts the account name on the console sign-in page and in the IAM dashboard,
# so it is visible at a glance which account a browser tab is pointed at. The
# name comes from the allowlist in locals.tf, so it cannot drift from the
# guardrail the provider enforces.
resource "aws_iam_account_alias" "this" {
  account_alias = local.account_name

  # local.account_name falls back to the bare account ID when the allowlist has
  # not been filled in. AWS rejects an all-digit alias anyway; catching it here
  # gives a message that says what to actually do about it.
  lifecycle {
    precondition {
      condition     = can(regex("^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$", local.account_name)) && !can(regex("^[0-9]+$", local.account_name))
      error_message = "No usable account alias for ${local.account_id}. Add it to local.allowed_accounts in locals.tf with a name of 3-63 lowercase letters, digits or hyphens."
    }
  }
}
