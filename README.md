# aws-account-setup

The first Terraform project to run against a brand new AWS account. It creates
what every other Terraform project in the account depends on, plus a minimal
audit baseline.

## What it configures

**State backend** (`state_backend.tf`)
- S3 bucket for Terraform state — versioned, with superseded versions expiring.
- Its own customer-managed KMS key, key rotation on, S3 Bucket Keys on.
- Bucket policy denies non-TLS requests and any write routing around the key.
- Locking is S3-native (`use_lockfile`). No DynamoDB table.

**Audit trail** (`cloudtrail.tf`)
- **Trail** — `var.cloudtrail_name` (default `account-activity`). Multi-region,
  global service events included, log file validation on. Two advanced event
  selectors, neither filtered on `readOnly`, so both capture reads and writes:
  all management events, and `AWS::S3::Object` data events under the state
  bucket.
- **Log bucket** — `cloudtrail-<account-id>-<region>`, or
  `var.cloudtrail_bucket_name`. Versioned, all four public access blocks on.
- **Object Lock** — enabled at bucket creation, default retention
  `var.cloudtrail_object_lock_mode` / `var.cloudtrail_object_lock_retention_days`
  (`GOVERNANCE`, 365 days).
- **Lifecycle** — objects expire after `var.cloudtrail_retention_days` (365),
  their noncurrent versions 30 days later; expired delete markers cleaned up;
  incomplete multipart uploads aborted after 7 days.
- **Encryption** — dedicated KMS key at `alias/cloudtrail`, rotation on, 30-day
  deletion window. Bucket default encryption is SSE-KMS with that key, S3
  Bucket Keys on.
- **Key policy** — account root `kms:*`; `cloudtrail.amazonaws.com` gets
  `GenerateDataKey*` and `DescribeKey`, conditioned on the trail ARN; account
  principals get `Decrypt` and `ReEncryptFrom` on log objects.
- **Bucket policy** — allows CloudTrail `GetBucketAcl` and `PutObject` under
  `AWSLogs/<account-id>/`, both conditioned on the trail ARN. Denies non-TLS
  requests, writes not using SSE-KMS, and writes naming any other KMS key.

**Account baseline** (`account_baseline.tf`), applied per region
- EBS encryption by default.
- IMDSv2 required on new EC2 instances (hop limit 2).
- IAM Access Analyzer (external access).
- IAM account alias, from the allowlist.

**Default VPCs** (`default_vpc.tf`, a phase of `just apply`)
- Deletes the default VPC, its subnets and its internet gateway in every
  *enabled* region, not just the operating ones.
- A Terraform `check` block warns on every plan if one comes back.

**Guardrails**
- `allowed_account_ids` from `locals.tf` — a stale `AWS_PROFILE` fails at plan.
- `prevent_destroy` on both buckets, both KMS keys, and the trail.

## Requirements

| Tool | Version | Why |
| --- | --- | --- |
| Brew | recent | Package manager used to install everything else |
| Terraform | >= 1.11 | S3 native state locking (`use_lockfile`) |
| AWS CLI | v2 | credentials and the preflight account check |
| just | recent | command runner (`brew install just`) |
| tflint, trivy | recent | lint and security scan |

You need to install `Brew` and `just` yourself, everything else is installed by calling: 

```bash
just setup
```

This command installs the AWS CLI, tenv, tflint and trivy from Homebrew, then has
[tenv](https://github.com/tofuutils/tenv) install and select the Terraform
version in `.terraform-version`. Re-running it is safe; already-installed
packages are skipped.

## Getting started

### 1. Replace the `<REPLACE_ME>` placeholders

Every value that must be hardcoded is marked `<REPLACE_ME>`. Find them with:

```bash
grep -rn '<REPLACE_ME>' --include='*.tf' .
```

### 2. Set your variables

```bash
cp terraform.tfvars.example terraform.tfvars   # gitignored
```

`aws_region` is the only required value — the example ships `us-east-1`, so
change it if that is not where the state bucket and trail belong. Everything
else is commented out with its default. Worth a look before the first apply:

- `operating_regions` — every *other* region the account runs things in. The
  baseline settings are per-region, so a region left off gets none of them
  (unencrypted EBS root volumes, IMDSv1, no analyzer). The trail is
  multi-region regardless. Opt-in regions must be enabled on the account first.
- `state_key_user_arns` — role ARNs allowed to decrypt state. Empty is a real
  choice (the key still gates access independently of IAM and logs every
  `Decrypt`); filling it in adds separation of duty. Use role ARNs, not the
  `assumed-role` session ARN `get-caller-identity` prints, and include every
  role that runs Terraform — anything left off gets AccessDenied on state.
- `cloudtrail_object_lock_*` — Object Lock can only be enabled at bucket
  creation, so decide before the first apply. `COMPLIANCE` cannot be bypassed
  by anyone, including the account root, for the full retention period.

### 3. Apply

```bash
just apply
```

Both phases run inside this one command. On a first run it stops for input
twice:

1. **Phase 1** — `check` runs, then `terraform apply` shows the plan and prompts.
   Answer `yes`. The buckets, KMS keys, and trail are created, and state lands
   in a local `terraform.tfstate`.
2. **Phase 2** — the generated backend block is printed and it asks
   `Migrate state now? [y/N]`. Answer `y`. `terraform init -migrate-state`
   copies the local state into the bucket phase 1 just created.

Later runs see `backend.tf` and stop after phase 1.

If phase 2 is skipped — you answered `N`, or there was no terminal to prompt on
— state is still on local disk and unprotected. Finish it with:

```bash
just migrate
```

Same command if a migration is interrupted: `backend.tf` is rolled back on
failure and `terraform.tfstate.backup` holds a copy of the state, so `just
migrate` picks up from either.

### 4. Commit `backend.tf`

Phase 2 generates it. It holds a bucket name and a KMS key ARN, neither secret,
and is how the next person inits against the same backend instead of starting a
fresh local state.

## Why the bootstrap has two phases

This project creates the bucket that stores Terraform state, so on the first
run there is nowhere remote to put its own state. The `backend.tf` is generated after the the 2 phased apply is complete in order to point to the bucket that was just created in the phase 1 apply.

## Wiring up other projects

`terraform output -raw downstream_backend_config` prints the block to paste
into every other Terraform project in the account. Change `key` to something unique per project:

```hcl
terraform {
  backend "s3" {
    bucket       = "tfstate-<account-id>-<region>"
    key          = "<project-name>/terraform.tfstate"
    region       = "<region>"
    encrypt      = true
    kms_key_id   = "arn:aws:kms:..."
    use_lockfile = true
  }
}
```

Callers need `kms:Decrypt` and `kms:GenerateDataKey` on the state key on top of
S3 access — and, if `state_key_user_arns` is set, a place on that list.

## Just Commands

| Just Command | What it does |
| --- | --- |
| `just` | list all commands |
| `just setup` | one-time: install the AWS CLI, tenv, Terraform, tflint, trivy |
| `just check` | preflight, `fmt -check`, `validate`, `tflint`, `trivy` |
| `just apply` | `check`, delete default VPCs, apply, then migrate state on first run |
| `just plan` | `check`, then `terraform plan` |
| `just fmt` | rewrite files to canonical formatting |
| `just migrate` | finish a skipped or interrupted state migration |
| `just clean` | remove local Terraform working files |

`check` is a dependency of `apply` and `plan`, so nothing is applied without
passing it. tflint checks correctness and style; trivy is what catches an
over-open policy, failing on `HIGH` and `CRITICAL`. With no CI, `just check` is
the only gate a change passes. A missing tool warns and skips rather than
blocking.

## Design notes

Why the code is written the way it is — the parts that are easy to undo by
accident.

**Encryption**
- Each bucket gets its own customer-managed key. A key is an access boundary,
  and reading audit logs should not imply being able to decrypt state.
- The state key keeps AWS's default account-root `kms:*` statement — removing
  it is how people lock themselves out of a key permanently. `state_key_user_arns`
  narrows access with a `Deny` on top, because policy statements are additive
  and only a `Deny` can take anything away. `kms:PutKeyPolicy` sits outside that
  deny and the root is exempt, so an over-tight list is recoverable.
- Both bucket policies deny writes that route around the key, because default
  bucket encryption is a default and not a constraint. The conditions use
  `StringNotEqualsIfExists`; the `IfExists` is load-bearing. Under plain
  `StringNotEquals` a request with no encryption header has no value to compare,
  the negated match is true, the `Deny` fires, and every write to the bucket
  fails.

**CloudTrail**
- Declaring any `advanced_event_selector` replaces the implicit
  all-management-events default, so the management selector is not redundant.
  Deleting it silently turns management event logging off.
- Object-level logging is scoped to the state bucket rather than account-wide,
  because data events are billed per event. It answers the question management
  events cannot: who *read* state, which holds credentials in plaintext.
- `enable_log_file_validation` proves after the fact that a log was altered;
  Object Lock stops it happening. `GOVERNANCE` bypass needs
  `s3:BypassGovernanceRetention` and is itself logged; `COMPLIANCE` has no
  escape hatch at all, so a mistaken retention is unrecoverable.
- Object Lock retention must not exceed `cloudtrail_retention_days`, and a
  validation enforces it. Otherwise the lifecycle expiry fails nightly and the
  logs accumulate forever while still being billed.

**Baseline**
- IMDSv2 is the account *default*, not a constraint — a launch explicitly
  asking for `optional` still gets it. Hop limit is 2, not 1: 1 means the
  instance itself only, which breaks containers, and ECS on EC2 and EKS both
  need 2.
- `prevent_destroy` guards `terraform destroy` only. It does not stop a console
  deletion or a `StopLogging` call, and does not fire if the resource is removed
  from the config first.

**Default VPCs**
- Every account is born with a default VPC per enabled region: a public subnet
  per AZ, an internet gateway, a `0.0.0.0/0` route. The regions you do not
  operate in are the ones carrying the risk, because nobody is looking at them,
  so the removal covers all enabled regions rather than `operating_regions`.
- It runs as a phase of `just apply`, between `check` and `terraform apply`, so
  the bootstrap is one command and the removal cannot be forgotten or run wrong.
  There is no separate command for it; re-running `just apply` is what cleans up
  a newly enabled region, and it is a no-op when there is nothing to delete.
- It is a `just` recipe plus a `check` block, not a Terraform resource, because
  Terraform cannot say "this must not exist". `aws_default_vpc` is an *adoption*
  resource and under provider v6 it will *create* a default VPC when none
  exists — a permanent block for it would rebuild what was just deleted. So:
  delete imperatively once, assert declaratively forever.
- The `check` failure is a warning, not an error. It will not block an unrelated
  apply, which is the right severity for drift whose fix is a separate command.
- The recipe surveys every region before deleting anything and aborts outright
  if any default VPC still has a network interface in it. A half-finished run
  across 17 regions is worse than no run — and because it is a dependency of
  `apply`, that abort stops the bootstrap before Terraform touches anything.
- **What this breaks**: anything that assumes a default VPC exists — the EC2
  launch wizard, RDS and ElastiCache quick-create, the Lambda-in-VPC picker,
  SageMaker Studio, Glue, EMR, Cloud9, and most copy-paste tutorials — reports
  "no default VPC found". Recovery is
  `aws ec2 create-default-vpc --region <region>`, but the rebuilt VPC, subnets
  and security group get **new IDs**, so anything that hardcoded the old ones
  stays broken.
- Enabling a new region later gives it a fresh default VPC. The `check` block is
  what tells you; `just apply` is what clears it.

**Not included**
- No account-level public access block; the blocks here cover this project's own
  buckets only.
- No IAM account password policy — add `aws_iam_account_password_policy` if the
  account has IAM users with console passwords.
- No CloudWatch alarms or metric filters on the trail.
- No GuardDuty, Security Hub, or Config. All three are usage-billed; IAM Access
  Analyzer is the free external-access check and is enabled.
- No DynamoDB lock table. Terraform 1.10 added `use_lockfile` and 1.11
  deprecated `dynamodb_table`.
