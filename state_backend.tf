locals {
  # account_id and partition live in locals.tf.
  state_bucket_name = coalesce(
    var.terraform_state_bucket_name,
    "tfstate-${local.account_id}-${var.aws_region}",
  )
}

resource "aws_s3_bucket" "terraform_state" {
  bucket = local.state_bucket_name

  # Losing this bucket means losing the state for every project in the account.
  lifecycle {
    prevent_destroy = true
  }
}

# Versioning is the recovery mechanism for a corrupted or truncated state file.
resource "aws_s3_bucket_versioning" "terraform_state" {
  bucket = aws_s3_bucket.terraform_state.id

  versioning_configuration {
    status = "Enabled"
  }
}

# The key carries an explicit policy rather than falling back to the one AWS
# writes for you. That default is a single statement handing the account root
# kms:*, which delegates every decision to IAM: anyone whose IAM policy allows
# KMS can read state, and the key is a compliance checkbox rather than a
# control. The statement below is kept -- dropping it is how people lock
# themselves out of a key permanently -- and the Deny after it is what turns
# the key into a second gate.
data "aws_iam_policy_document" "terraform_state_key" {
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

  # Only rendered once the operators are named. An Allow cannot narrow
  # anything, since policy statements are additive, so confining access has to
  # be a Deny. kms:PutKeyPolicy is deliberately absent from the action list:
  # whatever this denies, the policy itself can always be rewritten.
  dynamic "statement" {
    for_each = length(var.state_key_user_arns) > 0 ? [1] : []

    content {
      sid    = "ConfineCryptoOperationsToStateOperators"
      effect = "Deny"

      principals {
        type        = "AWS"
        identifiers = ["*"]
      }

      actions = [
        "kms:Encrypt",
        "kms:Decrypt",
        "kms:ReEncrypt*",
        "kms:GenerateDataKey*",
      ]

      resources = ["*"]

      # aws:PrincipalArn resolves an assumed-role session back to its role, so
      # the values here are role ARNs. The account root stays exempt as a
      # break-glass path back into the state files.
      condition {
        test     = "ArnNotEquals"
        variable = "aws:PrincipalArn"
        values = concat(
          var.state_key_user_arns,
          ["arn:${local.partition}:iam::${local.account_id}:root"],
        )
      }
    }
  }
}

# State gets its own key rather than sharing one with the CloudTrail bucket.
# A KMS key is an access boundary, and the two buckets have different
# audiences: state is read by whoever runs Terraform, audit logs by whoever
# reviews them. Separate keys keep those revocable independently.
resource "aws_kms_key" "terraform_state" {
  description             = "Encrypts the contents of the ${local.state_bucket_name} bucket"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.terraform_state_key.json

  # Deleting this key makes every state file in the bucket unreadable.
  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_kms_alias" "terraform_state" {
  name          = "alias/terraform-state"
  target_key_id = aws_kms_key.terraform_state.key_id
}

resource "aws_s3_bucket_server_side_encryption_configuration" "terraform_state" {
  bucket = aws_s3_bucket.terraform_state.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.terraform_state.arn
      sse_algorithm     = "aws:kms"
    }

    # Without this, every state read and write is a separate KMS API call.
    # S3 Bucket Keys cut that by roughly 99%.
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "terraform_state" {
  bucket = aws_s3_bucket.terraform_state.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# State is rewritten on every apply, so noncurrent versions pile up
# indefinitely without an expiry rule.
resource "aws_s3_bucket_lifecycle_configuration" "terraform_state" {
  bucket = aws_s3_bucket.terraform_state.id

  depends_on = [aws_s3_bucket_versioning.terraform_state]

  rule {
    id     = "expire-noncurrent-state-versions"
    status = "Enabled"

    filter {}

    noncurrent_version_expiration {
      noncurrent_days           = var.state_noncurrent_version_retention_days
      newer_noncurrent_versions = 10
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

data "aws_iam_policy_document" "terraform_state" {
  statement {
    sid    = "DenyInsecureTransport"
    effect = "Deny"

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    actions = ["s3:*"]

    resources = [
      aws_s3_bucket.terraform_state.arn,
      "${aws_s3_bucket.terraform_state.arn}/*",
    ]

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }

  # Default bucket encryption is a default, not a constraint: a PutObject that
  # explicitly asks for AES256 gets SSE-S3 and silently bypasses the KMS key,
  # taking the key policy and its audit trail with it. These two statements
  # make the default the only option.
  #
  # Both use StringNotEqualsIfExists, and the IfExists is load-bearing. A
  # request that sends no encryption header at all -- which is the normal case,
  # since the bucket default already applies the right key -- has no value for
  # these condition keys. Under a plain StringNotEquals, an absent key makes
  # the negated comparison true, the Deny fires, and every write to the bucket
  # fails, including the ones from the backend that owns it. IfExists skips the
  # statement when the header is absent and evaluates it when it is present,
  # which is exactly the "only override wrongly" case being denied.
  statement {
    sid    = "DenyNonKmsEncryption"
    effect = "Deny"

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.terraform_state.arn}/*"]

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
    resources = ["${aws_s3_bucket.terraform_state.arn}/*"]

    condition {
      test     = "StringNotEqualsIfExists"
      variable = "s3:x-amz-server-side-encryption-aws-kms-key-id"
      values   = [aws_kms_key.terraform_state.arn]
    }
  }
}

resource "aws_s3_bucket_policy" "terraform_state" {
  bucket = aws_s3_bucket.terraform_state.id
  policy = data.aws_iam_policy_document.terraform_state.json

  depends_on = [aws_s3_bucket_public_access_block.terraform_state]
}
