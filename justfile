# Local bootstrap workflow for a fresh AWS account.
# Run `just` with no arguments to see what's available.

set shell := ["bash", "-euo", "pipefail", "-c"]

tf_min_version := "1.11.0"
backend_file   := "backend.tf"

# Show available commands.
default:
    @just --list --unsorted

# One-time: install everything the rest of this justfile expects.
setup:
    #!/usr/bin/env bash
    set -euo pipefail

    if ! command -v brew >/dev/null 2>&1; then
        echo "Homebrew not found. Install awscli, tenv, tflint and trivy manually." >&2
        exit 1
    fi

    install() {
        if brew list --versions "$1" >/dev/null 2>&1; then
            printf '  already installed: %s\n' "${1##*/}"
        else
            brew install "$1"
        fi
    }

    printf '\033[1m→ packages\033[0m\n'
    install awscli
    # Terraform comes from tenv, not Homebrew: homebrew-core's formula is frozen
    # at 1.5.7 since the BUSL change, and hashicorp/tap is unbottled.
    install tenv
    # tflint ships from its own tap rather than homebrew-core.
    install terraform-linters/tap/tflint
    install trivy

    printf '\n\033[1m→ terraform\033[0m\n'
    version=$(cat .terraform-version)
    tenv tf install "$version"
    tenv tf use "$version"

    printf '\n\033[1m→ tflint plugins\033[0m\n'
    tflint --init

    printf '\n\033[32m✓ setup complete\033[0m\n'
    if ! aws sts get-caller-identity >/dev/null 2>&1; then
        printf '  Next: configure AWS credentials (`aws configure sso`, or export AWS_PROFILE).\n'
    fi

# Everything a change should pass before it is applied: format, validate, lint, scan.
check: _preflight _fmt-check _validate _lint _scan
    @printf '\n\033[32m✓ all checks passed\033[0m\n'

# Full bootstrap: checks, delete default VPCs, apply, then migrate state.
apply: check _default-vpcs
    #!/usr/bin/env bash
    set -euo pipefail

    terraform apply

    if [[ -f "{{ backend_file }}" ]]; then
        printf '\n\033[32m✓ apply complete\033[0m (state already remote)\n'
        exit 0
    fi

    # First run. State is sitting in a local terraform.tfstate that nothing is
    # backing up, so move it into the bucket that was just created.
    printf '\n\033[1mPhase 2: migrating state into the new bucket\033[0m\n\n'

    # Held in a variable rather than written straight to disk. A backend file
    # sitting next to state that is still local wedges every later run: the
    # preflight `init -input=false` has to ask the migration question and
    # cannot, so it fails with an opaque error. The file goes to disk only
    # once the migration is about to run, and comes back off if it does not
    # finish.
    backend_config=$(terraform output -raw backend_config)
    printf '%s\n' "$backend_config"

    if [[ ! -t 0 ]]; then
        printf '\n\033[33mSkipped:\033[0m no terminal to confirm on. State is still local and unprotected.\n' >&2
        printf 'Run `just migrate` from a terminal to finish the bootstrap.\n' >&2
        exit 0
    fi

    printf '\nThis moves local state into S3 and leaves a terraform.tfstate.backup behind.\n'
    read -r -p 'Migrate state now? [y/N] ' reply
    if [[ ! "$reply" =~ ^[Yy]$ ]]; then
        printf '\n\033[33mSkipped.\033[0m State is still local and unprotected.\n'
        printf 'Re-run `just apply`, or `just migrate` on its own, when ready.\n'
        exit 0
    fi

    migrated=0
    rollback() {
        if [[ "$migrated" -eq 0 ]]; then
            rm -f "{{ backend_file }}"
            printf '\n\033[33mMigration did not finish; rolled back %s.\033[0m\n' "{{ backend_file }}" >&2
            printf 'State is still local, and terraform.tfstate.backup holds a copy.\n' >&2
            printf 'Re-run `just apply` to try again.\n' >&2
        fi
    }
    trap rollback EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM

    printf '%s\n' "$backend_config" > "{{ backend_file }}"
    terraform init -migrate-state -force-copy
    migrated=1

    printf '\n\033[32m✓ bootstrap complete\033[0m\n'
    printf '  Commit %s so the next person inits against the same backend.\n' "{{ backend_file }}"
    printf '  Run `terraform output -raw downstream_backend_config` for the block other projects should use.\n'

# Preview changes without applying.
plan: check
    terraform plan

# Migrate local state into the S3 backend. Needed if `just apply` skipped or interrupted it.
migrate:
    #!/usr/bin/env bash
    set -euo pipefail

    # A finished migration truncates terraform.tfstate to zero bytes, so a
    # non-empty one means the state is still on local disk whatever the
    # backend file says.
    if [[ -f "{{ backend_file }}" ]]; then
        if [[ ! -s terraform.tfstate ]]; then
            echo "{{ backend_file }} exists and local state is empty; state is already remote." >&2
            exit 1
        fi
        printf '\033[33m%s exists but state is still local.\033[0m Finishing the migration.\n\n' "{{ backend_file }}"
        terraform init -migrate-state
        exit 0
    fi

    migrated=0
    rollback() {
        if [[ "$migrated" -eq 0 ]]; then
            rm -f "{{ backend_file }}"
            printf '\n\033[33mMigration did not finish; rolled back %s.\033[0m\n' "{{ backend_file }}" >&2
        fi
    }
    trap rollback EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM

    terraform output -raw backend_config > "{{ backend_file }}"
    terraform init -migrate-state
    migrated=1

# Rewrite files to canonical formatting.
fmt:
    terraform fmt -recursive

# Remove local Terraform working files. Does not touch remote state.
clean:
    rm -rf .terraform .terraform.tfstate.lock.info tfplan

# --- internals -------------------------------------------------------------

_default-vpcs:
    #!/usr/bin/env bash
    set -euo pipefail

    printf '\033[1m→ surveying enabled regions\033[0m\n'
    regions=$(aws ec2 describe-regions --query 'Regions[].RegionName' --output text)

    # Survey everything before deleting anything. A region whose default VPC
    # still has an ENI in it means something is actually running in there, and
    # that has to stop the whole run -- not leave the account half-done with
    # the busy region somewhere in the middle of the list.
    targets=()
    blocked=()
    for region in $regions; do
        vpc=$(aws ec2 describe-vpcs --region "$region" \
            --filters Name=isDefault,Values=true \
            --query 'Vpcs[0].VpcId' --output text)

        if [[ "$vpc" == "None" || -z "$vpc" ]]; then
            printf '  %-16s already clean\n' "$region"
            continue
        fi

        enis=$(aws ec2 describe-network-interfaces --region "$region" \
            --filters Name=vpc-id,Values="$vpc" \
            --query 'NetworkInterfaces[].NetworkInterfaceId' --output text)

        if [[ -n "$enis" ]]; then
            printf '  \033[31m%-16s %s is IN USE\033[0m: %s\n' "$region" "$vpc" "$enis"
            blocked+=("$region")
        else
            printf '  %-16s %s\n' "$region" "$vpc"
            targets+=("$region:$vpc")
        fi
    done

    if [[ ${#blocked[@]} -gt 0 ]]; then
        printf '\n\033[31mAborted.\033[0m Network interfaces exist in the default VPC in: %s\n' "${blocked[*]}" >&2
        printf 'Something is running in there. Find out what, move or delete it, then re-run.\n' >&2
        exit 1
    fi

    if [[ ${#targets[@]} -eq 0 ]]; then
        printf '\n\033[32m✓ nothing to do\033[0m: no default VPC in any enabled region.\n'
        exit 0
    fi

    printf '\n\033[1mThis deletes %d default VPCs\033[0m, with their subnets, internet\n' "${#targets[@]}"
    printf 'gateways, route tables and default security groups.\n'
    printf 'Recovery is `aws ec2 create-default-vpc --region <r>`, but the rebuilt\n'
    printf 'VPC, subnets and security group get new IDs.\n'

    if [[ ! -t 0 ]]; then
        printf '\n\033[33mSkipped:\033[0m no terminal to confirm on. Default VPCs are still there.\n' >&2
        printf 'Re-run `just apply` from a terminal to finish the bootstrap.\n' >&2
        exit 0
    fi

    read -r -p $'\nDelete them? [y/N] ' reply
    if [[ ! "$reply" =~ ^[Yy]$ ]]; then
        printf '\n\033[33mSkipped.\033[0m Nothing was deleted; `just plan` warns until it is.\n'
        exit 0
    fi

    printf '\n\033[1m→ deleting\033[0m\n'
    for target in "${targets[@]}"; do
        region="${target%%:*}"
        vpc="${target##*:}"

        # Order matters, and only these three calls are needed. The default
        # security group, route table and network ACL are deleted along with
        # the VPC -- and the default security group cannot be deleted on its
        # own, so asking for it would only produce a confusing failure.
        subnets=$(aws ec2 describe-subnets --region "$region" \
            --filters Name=vpc-id,Values="$vpc" \
            --query 'Subnets[].SubnetId' --output text)
        for subnet in $subnets; do
            aws ec2 delete-subnet --region "$region" --subnet-id "$subnet"
        done

        igws=$(aws ec2 describe-internet-gateways --region "$region" \
            --filters Name=attachment.vpc-id,Values="$vpc" \
            --query 'InternetGateways[].InternetGatewayId' --output text)
        for igw in $igws; do
            aws ec2 detach-internet-gateway --region "$region" \
                --internet-gateway-id "$igw" --vpc-id "$vpc"
            aws ec2 delete-internet-gateway --region "$region" \
                --internet-gateway-id "$igw"
        done

        aws ec2 delete-vpc --region "$region" --vpc-id "$vpc"
        printf '  \033[32m✓\033[0m %-16s %s\n' "$region" "$vpc"
    done

    printf '\n\033[32m✓ deleted %d default VPCs\033[0m\n' "${#targets[@]}"

_preflight:
    #!/usr/bin/env bash
    set -euo pipefail

    if ! command -v terraform >/dev/null 2>&1; then
        echo "terraform not found on PATH." >&2
        exit 1
    fi

    # `terraform version` prints "Terraform vX.Y.Z" on its first line, and
    # sometimes an upgrade notice after it. NR==1 takes the version line, and
    # substr drops the leading "v". Deliberately not `version -json` piped
    # through python3: this is the one thing standing between a stale Terraform
    # and a confusing backend error, and it should not depend on whatever a
    # pyenv shim resolves to today.
    current=$(terraform version | awk 'NR==1 {print substr($2, 2)}')
    oldest=$(printf '%s\n%s\n' "$current" "{{ tf_min_version }}" | sort -V | head -1)
    if [[ "$oldest" != "{{ tf_min_version }}" && "$current" != "{{ tf_min_version }}" ]]; then
        echo "Terraform $current is too old; this project needs >= {{ tf_min_version }}." >&2
        echo "S3 native state locking (use_lockfile) is not available before then." >&2
        echo >&2
        echo "Terraform here is managed by tenv, which reads .terraform-version:" >&2
        echo "  tenv tf install \$(cat .terraform-version)" >&2
        echo "  tenv tf use \$(cat .terraform-version)" >&2
        echo >&2
        echo "Not \`brew upgrade terraform\`: homebrew-core's formula is frozen at 1.5.7" >&2
        echo "since the BUSL change, and hashicorp/tap is unbottled, so Homebrew treats" >&2
        echo "it as a source build and refuses when the Command Line Tools are outdated." >&2
        exit 1
    fi

    if ! aws sts get-caller-identity >/dev/null 2>&1; then
        echo "No usable AWS credentials. Configure a profile or export AWS_PROFILE." >&2
        exit 1
    fi

    account=$(aws sts get-caller-identity --query Account --output text)
    printf '\033[1mterraform\033[0m %s  \033[1maccount\033[0m %s\n\n' "$current" "$account"

    # `init -input=false` cannot ask the state migration question, so a backend
    # file next to state that is still local fails it with an error that does
    # not say what to do. Newer runs roll that combination back on their own;
    # this catches a checkout left in it by an older one.
    if [[ -f "{{ backend_file }}" && -s terraform.tfstate ]]; then
        echo "{{ backend_file }} points at a remote backend, but terraform.tfstate still holds local state." >&2
        echo "A previous migration did not finish. Run \`just migrate\` to complete it -- it shows" >&2
        echo "what it is about to copy before doing anything. If you know the state is already in" >&2
        echo "S3, delete the stale terraform.tfstate instead." >&2
        exit 1
    fi

    terraform init -input=false

_fmt-check:
    @printf '\033[1m→ fmt\033[0m\n'
    @terraform fmt -recursive -check -diff

_validate:
    @printf '\033[1m→ validate\033[0m\n'
    @terraform validate

_lint:
    #!/usr/bin/env bash
    set -euo pipefail
    printf '\033[1m→ lint\033[0m\n'
    if ! command -v tflint >/dev/null 2>&1; then
        printf '\033[33m  skipped: tflint not installed (run `just setup`)\033[0m\n'
        exit 0
    fi
    tflint --init >/dev/null
    tflint --format compact

_scan:
    #!/usr/bin/env bash
    set -euo pipefail
    printf '\033[1m→ scan\033[0m\n'
    if ! command -v trivy >/dev/null 2>&1; then
        printf '\033[33m  skipped: trivy not installed (run `just setup`)\033[0m\n'
        exit 0
    fi
    # tflint checks correctness and style; it will not tell you a policy is too
    # open. With no CI, `just check` is the only gate a change passes, so the
    # security scanner belongs here or nowhere.
    #
    # HIGH,CRITICAL is the failing threshold. The MEDIUM findings this repo
    # currently has are S3 access logging on the two buckets and CloudWatch
    # Logs on the trail, all three of which are deliberate omissions -- see the
    # Notes section of the README. Lowering the threshold means either acting
    # on those or maintaining an ignore file, and neither is worth it yet.
    trivy config --severity HIGH,CRITICAL --exit-code 1 .
