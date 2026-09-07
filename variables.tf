variable "aws_region" {
  description = "The AWS region your Terraform state bucket and audit trail will be deployed to."
  type        = string

  validation {
    condition     = can(regex("^[a-z]{2}(-gov)?-[a-z]+-[0-9]$", var.aws_region))
    error_message = "aws_region must look like an AWS region, e.g. us-east-1 or eu-west-2."
  }
}

variable "operating_regions" {
  description = <<-EOT
    Additional regions this AWS account operates in, beyond aws_region.

    Some account settings are per-region rather than account-wide: EBS
    encryption by default and IAM Access Analyzer both have to be turned on in
    each region separately. A region left off this list has neither, so an EC2
    instance launched there gets an unencrypted root volume.

    aws_region is always included and does not need repeating here. Opt-in
    regions (ap-east-1, me-south-1, and the rest) must be enabled on the
    account before they can be listed, or the apply fails against them.
  EOT
  type        = list(string)
  default     = []

  validation {
    condition = alltrue([
      for r in var.operating_regions :
      can(regex("^[a-z]{2}(-gov)?-[a-z]+-[0-9]$", r))
    ])
    error_message = "Each entry must look like an AWS region, e.g. us-east-1 or eu-west-2."
  }
}

variable "terraform_state_bucket_name" {
  description = <<-EOT
    Name of the S3 bucket used to store Terraform state. S3 bucket names are
    globally unique across all AWS accounts, so this needs to be something no
    one else has taken. Leave null to default to
    "tfstate-<account-id>-<region>", which is unique by construction.
  EOT
  type        = string
  default     = null

  validation {
    condition = var.terraform_state_bucket_name == null || can(regex(
      "^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$", var.terraform_state_bucket_name
    ))
    error_message = "Bucket name must be 3-63 characters of lowercase letters, numbers, dots or hyphens, starting and ending with a letter or number."
  }
}

variable "cloudtrail_bucket_name" {
  description = <<-EOT
    Name of the S3 bucket that stores CloudTrail logs. Kept separate from the
    state bucket so audit logs have their own retention and access policy.
    Leave null to default to "cloudtrail-<account-id>-<region>".
  EOT
  type        = string
  default     = null

  validation {
    condition = var.cloudtrail_bucket_name == null || can(regex(
      "^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$", var.cloudtrail_bucket_name
    ))
    error_message = "Bucket name must be 3-63 characters of lowercase letters, numbers, dots or hyphens, starting and ending with a letter or number."
  }
}

variable "cloudtrail_name" {
  description = "Name of the CloudTrail trail that records account activity."
  type        = string
  default     = "account-activity"
}

variable "cloudtrail_retention_days" {
  description = "How long to keep CloudTrail logs in S3 before deleting them."
  type        = number
  default     = 365

  validation {
    condition     = var.cloudtrail_retention_days >= 1
    error_message = "cloudtrail_retention_days must be at least 1."
  }
}

variable "cloudtrail_object_lock_mode" {
  description = <<-EOT
    S3 Object Lock mode for CloudTrail logs.

    GOVERNANCE means a log file cannot be overwritten or deleted before its
    retention expires, except by a principal holding
    s3:BypassGovernanceRetention -- and that bypass is itself an API call the
    trail records. COMPLIANCE removes the escape hatch entirely: for the
    retention period, nobody can delete those objects, including the account
    root and including AWS support, and you pay to store them either way.

    GOVERNANCE is the default because COMPLIANCE is unusually unforgiving of
    mistakes: a fat-fingered retention of "10 years" on a chatty trail is not
    recoverable at any price. Switch to COMPLIANCE when an auditor asks for it
    and the retention number has been checked twice.
  EOT
  type        = string
  default     = "GOVERNANCE"

  validation {
    condition     = contains(["GOVERNANCE", "COMPLIANCE"], var.cloudtrail_object_lock_mode)
    error_message = "cloudtrail_object_lock_mode must be GOVERNANCE or COMPLIANCE."
  }
}

variable "cloudtrail_object_lock_retention_days" {
  description = <<-EOT
    How long each CloudTrail log file is locked against deletion.

    Must not exceed cloudtrail_retention_days. A lock outlasting the lifecycle
    rule does not extend retention in any useful way -- it just makes the
    expiry silently fail and the storage bill keep growing.
  EOT
  type        = number
  default     = 365

  validation {
    condition     = var.cloudtrail_object_lock_retention_days >= 1
    error_message = "cloudtrail_object_lock_retention_days must be at least 1."
  }

  validation {
    condition     = var.cloudtrail_object_lock_retention_days <= var.cloudtrail_retention_days
    error_message = "cloudtrail_object_lock_retention_days must not exceed cloudtrail_retention_days, or the lifecycle expiry will fail and logs will accumulate forever."
  }
}

variable "state_noncurrent_version_retention_days" {
  description = <<-EOT
    How long to keep superseded versions of state files. Versioning is what
    lets you recover from a bad apply, but state is rewritten on every apply of
    every downstream project, so old versions need an expiry or they accumulate
    forever.
  EOT
  type        = number
  default     = 90

  validation {
    condition     = var.state_noncurrent_version_retention_days >= 1
    error_message = "state_noncurrent_version_retention_days must be at least 1."
  }
}

variable "state_key_user_arns" {
  description = <<-EOT
    IAM principal ARNs allowed to encrypt and decrypt Terraform state.

    Left empty, the state key delegates to IAM like any other key: anyone whose
    IAM policy grants KMS access can read state, and the key buys you an audit
    trail and cross-account protection but no separation of duty. Naming the
    roles that actually run Terraform makes the key a second gate in front of
    the state files.

    Use role ARNs (arn:aws:iam::<account>:role/<name>), not the assumed-role
    session ARNs that `aws sts get-caller-identity` prints -- aws:PrincipalArn
    resolves a session back to its role. Anything left off the list gets
    AccessDenied on state, including automation added later.
  EOT
  type        = list(string)
  default     = []

  validation {
    condition = alltrue([
      for arn in var.state_key_user_arns :
      can(regex("^arn:[a-z-]+:iam::[0-9]{12}:(role|user)/.+$", arn))
    ])
    error_message = "Each entry must be an IAM role or user ARN, e.g. arn:aws:iam::123456789012:role/terraform."
  }
}

variable "default_tags" {
  description = "Tags applied to every resource this project creates."
  type        = map(string)
  default = {
    owner      = "infrastructure"
    managed_by = "terraform"
    project    = "aws-account-setup"
  }
}
