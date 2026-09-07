provider "aws" {
  region = var.aws_region

  # Refuses to act against any account not named in locals.tf. This is the only
  # thing standing between a stale AWS_PROFILE and a full second copy of the
  # state backend built somewhere it does not belong -- the bucket names carry
  # the account ID, so a wrong-account apply would not even collide.
  allowed_account_ids = local.allowed_account_ids

  default_tags {
    tags = var.default_tags
  }
}

data "aws_caller_identity" "current" {}

data "aws_partition" "current" {}
