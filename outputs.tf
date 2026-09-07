output "state_bucket_name" {
  description = "Name of the S3 bucket holding Terraform state."
  value       = aws_s3_bucket.terraform_state.id
}

output "state_bucket_arn" {
  description = "ARN of the S3 bucket holding Terraform state."
  value       = aws_s3_bucket.terraform_state.arn
}

output "state_kms_key_arn" {
  description = "ARN of the KMS key encrypting Terraform state."
  value       = aws_kms_key.terraform_state.arn
}

output "state_kms_key_alias" {
  description = "Alias of the KMS key encrypting Terraform state."
  value       = aws_kms_alias.terraform_state.name
}

output "aws_region" {
  description = "Region the state bucket and trail live in."
  value       = var.aws_region
}

output "cloudtrail_bucket_name" {
  description = "Name of the S3 bucket holding CloudTrail logs."
  value       = aws_s3_bucket.cloudtrail.id
}

output "cloudtrail_arn" {
  description = "ARN of the CloudTrail trail recording account activity."
  value       = aws_cloudtrail.account_activity.arn
}

# Written to backend.tf by `just apply` on the first run, which is what moves
# this project's own state off the local disk and into the bucket it just made.
output "backend_config" {
  description = "Backend block for this project's own state."
  value       = <<-EOT
    terraform {
      backend "s3" {
        bucket       = "${aws_s3_bucket.terraform_state.id}"
        key          = "bootstrap/terraform.tfstate"
        region       = "${var.aws_region}"
        encrypt      = true
        kms_key_id   = "${aws_kms_key.terraform_state.arn}"
        use_lockfile = true
      }
    }
  EOT
}

# Copy this into every other Terraform project in the account, changing `key`
# to something unique per project.
output "downstream_backend_config" {
  description = "Backend block template for other Terraform projects in this account."
  value       = <<-EOT
    terraform {
      backend "s3" {
        bucket       = "${aws_s3_bucket.terraform_state.id}"
        key          = "<project-name>/terraform.tfstate"
        region       = "${var.aws_region}"
        encrypt      = true
        kms_key_id   = "${aws_kms_key.terraform_state.arn}"
        use_lockfile = true
      }
    }
  EOT
}
