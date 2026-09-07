locals {
  cloudtrail_bucket_name = coalesce(
    var.cloudtrail_bucket_name,
    "cloudtrail-${local.account_id}-${var.aws_region}",
  )

  # Built by hand rather than referenced off aws_cloudtrail. The trail needs the
  # bucket policy and KMS key to exist before it can be created, and both of
  # those need to name the trail, so referencing the resource would be a cycle.
  cloudtrail_arn = "arn:${local.partition}:cloudtrail:${var.aws_region}:${local.account_id}:trail/${var.cloudtrail_name}"
}

resource "aws_s3_bucket" "cloudtrail" {
  bucket = local.cloudtrail_bucket_name

  # Object Lock can only be turned on when the bucket is created, which is why
  # it is here rather than left as a later hardening step. Retention and mode
  # are configured separately, below.
  object_lock_enabled = true

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket_versioning" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_public_access_block" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id

  depends_on = [aws_s3_bucket_versioning.cloudtrail]

  rule {
    id     = "expire-logs"
    status = "Enabled"

    filter {}

    expiration {
      days = var.cloudtrail_retention_days
    }

    noncurrent_version_expiration {
      noncurrent_days = 30
    }
  }

  # The bucket is versioned, so the expiry above does not delete anything -- it
  # writes a delete marker and the real object becomes noncurrent. Thirty days
  # later noncurrent_version_expiration removes that version, leaving a delete
  # marker with nothing underneath it. Those are free to store but never
  # disappear on their own, and CloudTrail writes enough small objects that
  # they accumulate into something that slows every ListObjectVersions call.
  #
  # It has to be its own rule: S3 rejects a rule that sets
  # expired_object_delete_marker alongside a Days expiry.
  rule {
    id     = "clean-expired-delete-markers"
    status = "Enabled"

    filter {}

    expiration {
      expired_object_delete_marker = true
    }
  }

  rule {
    id     = "abort-incomplete-uploads"
    status = "Enabled"

    filter {}

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

# enable_log_file_validation proves after the fact that a log file was altered.
# This stops it happening: for the retention period, a log file cannot be
# overwritten or permanently deleted, by anyone, whatever their IAM policy says.
#
# The retention here is validated to be no longer than the lifecycle expiry.
# The other way round, the expiry would fail against the lock every night and
# the logs would sit there being billed forever.
resource "aws_s3_bucket_object_lock_configuration" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id

  rule {
    default_retention {
      mode = var.cloudtrail_object_lock_mode
      days = var.cloudtrail_object_lock_retention_days
    }
  }

  depends_on = [aws_s3_bucket_versioning.cloudtrail]
}

# --- KMS key for the trail -------------------------------------------------

data "aws_iam_policy_document" "cloudtrail_key" {
  statement {
    sid    = "EnableIAMPolicies"
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = ["arn:${local.partition}:iam::${local.account_id}:root"]
    }

    actions   = ["kms:*"]
    resources = ["*"]
  }

  statement {
    sid    = "AllowCloudTrailToEncryptLogs"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    actions   = ["kms:GenerateDataKey*"]
    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.cloudtrail_arn]
    }

    condition {
      test     = "StringLike"
      variable = "kms:EncryptionContext:aws:cloudtrail:arn"
      values   = ["arn:${local.partition}:cloudtrail:*:${local.account_id}:trail/*"]
    }
  }

  statement {
    sid    = "AllowCloudTrailToDescribeKey"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    actions   = ["kms:DescribeKey"]
    resources = ["*"]
  }

  # Without this, nobody in the account can actually read the logs back.
  statement {
    sid    = "AllowAccountPrincipalsToDecryptLogs"
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    actions = [
      "kms:Decrypt",
      "kms:ReEncryptFrom",
    ]
    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "kms:CallerAccount"
      values   = [local.account_id]
    }

    condition {
      test     = "StringLike"
      variable = "kms:EncryptionContext:aws:cloudtrail:arn"
      values   = ["arn:${local.partition}:cloudtrail:*:${local.account_id}:trail/*"]
    }
  }
}

resource "aws_kms_key" "cloudtrail" {
  description             = "Encrypts CloudTrail logs in ${local.cloudtrail_bucket_name}"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.cloudtrail_key.json

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_kms_alias" "cloudtrail" {
  name          = "alias/cloudtrail"
  target_key_id = aws_kms_key.cloudtrail.key_id
}

resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.cloudtrail.arn
      sse_algorithm     = "aws:kms"
    }

    bucket_key_enabled = true
  }
}

# --- Bucket policy ---------------------------------------------------------

data "aws_iam_policy_document" "cloudtrail_bucket" {
  statement {
    sid    = "AWSCloudTrailAclCheck"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.cloudtrail.arn]

    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.cloudtrail_arn]
    }
  }

  statement {
    sid    = "AWSCloudTrailWrite"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.cloudtrail.arn}/AWSLogs/${local.account_id}/*"]

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.cloudtrail_arn]
    }
  }

  statement {
    sid    = "DenyInsecureTransport"
    effect = "Deny"

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    actions = ["s3:*"]

    resources = [
      aws_s3_bucket.cloudtrail.arn,
      "${aws_s3_bucket.cloudtrail.arn}/*",
    ]

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }

  # Same reasoning as the state bucket: bucket default encryption is only a
  # default, and an explicit AES256 header would quietly route log files around
  # the KMS key. IfExists is what keeps a header-less write -- which is what
  # CloudTrail may well send, since the bucket default already applies the
  # right key -- from tripping the Deny and breaking the trail.
  statement {
    sid    = "DenyNonKmsEncryption"
    effect = "Deny"

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.cloudtrail.arn}/*"]

    condition {
      test     = "StringNotEqualsIfExists"
      variable = "s3:x-amz-server-side-encryption"
      values   = ["aws:kms"]
    }
  }

  statement {
    sid    = "DenyWrongKmsKey"
    effect = "Deny"

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.cloudtrail.arn}/*"]

    condition {
      test     = "StringNotEqualsIfExists"
      variable = "s3:x-amz-server-side-encryption-aws-kms-key-id"
      values   = [aws_kms_key.cloudtrail.arn]
    }
  }
}

resource "aws_s3_bucket_policy" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id
  policy = data.aws_iam_policy_document.cloudtrail_bucket.json

  depends_on = [aws_s3_bucket_public_access_block.cloudtrail]
}

# --- The trail -------------------------------------------------------------

# Management events for the whole account, plus object-level events for the
# Terraform state bucket and nothing else.
#
# Data events are billed per event, which is why they are not on account-wide:
# S3 object-level logging across every bucket in a busy account gets expensive
# fast. Scoped to the state bucket the volume is a handful of events per apply,
# and it answers the one question management events cannot -- who read state.
# State files hold provider credentials and generated secrets in plaintext, so
# a read of one is a credential disclosure whether or not anything else happens.
#
# Note that declaring any advanced_event_selector replaces the implicit
# all-management-events default, so the management selector below is not
# redundant. Dropping it would silently turn off management event logging.
resource "aws_cloudtrail" "account_activity" {
  name           = var.cloudtrail_name
  s3_bucket_name = aws_s3_bucket.cloudtrail.id
  kms_key_id     = aws_kms_key.cloudtrail.arn

  is_multi_region_trail         = true
  include_global_service_events = true
  enable_log_file_validation    = true

  advanced_event_selector {
    name = "Management events"

    field_selector {
      field  = "eventCategory"
      equals = ["Management"]
    }
  }

  # No readOnly selector, so this captures both reads and writes.
  advanced_event_selector {
    name = "Terraform state object access"

    field_selector {
      field  = "eventCategory"
      equals = ["Data"]
    }

    field_selector {
      field  = "resources.type"
      equals = ["AWS::S3::Object"]
    }

    field_selector {
      field       = "resources.ARN"
      starts_with = ["${aws_s3_bucket.terraform_state.arn}/"]
    }
  }

  depends_on = [
    aws_s3_bucket_policy.cloudtrail,
    aws_s3_bucket_server_side_encryption_configuration.cloudtrail,
  ]

  # Both buckets and both keys carry this; the trail needs it for the same
  # reason. Object Lock makes the logs already written indestructible, which is
  # worth nothing if the thing writing them is gone -- a destroy here leaves an
  # immutable archive that silently stops at the moment it was removed. Note
  # the usual caveat: this stops `terraform destroy`, not a StopLogging call or
  # a deletion in the console, and it does not fire if the resource is taken
  # out of the config first.
  lifecycle {
    prevent_destroy = true
  }
}
