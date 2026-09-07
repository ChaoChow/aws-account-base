locals {
  # --- Account allowlist ---------------------------------------------------

  # The accounts this project is allowed to touch, keyed by account ID.
  #
  # Deliberately not a variable. An allowlist that can be overridden from a
  # tfvars file is a suggestion, not a guardrail -- and tfvars is gitignored,
  # so an override would not even be reviewable. Editing this file is a code
  # change someone sees, which is the entire point of the control.
  #
  # The provider refuses to do anything when the ambient credentials resolve
  # to an account that is not a key here, so a stale AWS_PROFILE fails
  # immediately instead of quietly building a second, parallel state backend
  # in the wrong account. Nothing else in this project would catch that: the
  # bucket names default to "<purpose>-<account-id>-<region>", so they would
  # not even collide.
  #
  # The key is the 12-digit account ID; the value is the account alias, 3-63
  # lowercase letters, digits or hyphens, and not all digits. Both ship as
  # <REPLACE_ME> and nothing will apply until they are filled in.
  allowed_accounts = {
    "<REPLACE_ME>" = "<REPLACE_ME>"
  }

  allowed_account_ids = keys(local.allowed_accounts)

  # --- Identity of the account being applied to ----------------------------

  account_id = data.aws_caller_identity.current.account_id
  partition  = data.aws_partition.current.partition

  # Falls back to the raw ID rather than erroring on a map miss, so that the
  # provider's own allowed_account_ids check is what reports a wrong account.
  # Its message names the offending ID; a Terraform map lookup failure does not.
  account_name = lookup(local.allowed_accounts, local.account_id, local.account_id)

  # --- Regions -------------------------------------------------------------

  # Region-scoped account settings (EBS encryption, Access Analyzer) are
  # applied to every region here. aws_region is always included: it is where
  # the buckets and the trail live, so it is never not an operating region.
  operating_regions = distinct(concat([var.aws_region], var.operating_regions))
}
