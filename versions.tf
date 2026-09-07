terraform {
  # 1.11 is the floor: `use_lockfile` (S3 native state locking) became a
  # non-experimental backend option there, which is what lets us drop the
  # DynamoDB lock table entirely.
  required_version = ">= 1.11"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}
