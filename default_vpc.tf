# --- Default VPCs ----------------------------------------------------------

# Every AWS account is born with a default VPC in every enabled region: a
# public subnet per availability zone, an internet gateway, a 0.0.0.0/0 route,
# and a default security group. That is internet-reachable network capacity in
# a dozen regions nobody looks at, which is where an unattended compromise
# actually lands. It also means a console click can put an instance on a public
# subnet without anyone having decided a network was needed.
#
# So they get deleted -- in every enabled region, not just the operating ones,
# because the unused regions are the ones carrying the risk.
#
# The deletion itself is a phase of `just apply`, not a resource here, and that
# is deliberate. Terraform cannot say "this must not exist".
# `aws_default_vpc` is an adoption resource: it adopts the existing default
# VPC, and under provider v6 it *creates* one when none exists. A permanent
# block for it would rebuild the thing we just deleted on the next apply. The
# adopt-then-delete-the-block dance reaches the same end state but leaves a
# config that is actively wrong to re-add.
#
# What lives here instead is the standing assertion: delete imperatively once,
# then notice forever if one comes back. One does come back when a new region
# is enabled, or when somebody runs `aws ec2 create-default-vpc` to unblock a
# tutorial. The fix in both cases is another `just apply`.

# Only the regions enabled on this account. Deliberately not
# local.operating_regions -- a default VPC in a region we do not operate in is
# the whole point.
data "aws_regions" "enabled" {}

# Returns an empty ids list rather than erroring when a region is clean, which
# is what makes the assertion below readable.
data "aws_vpcs" "default" {
  for_each = toset(data.aws_regions.enabled.names)

  region = each.value

  filter {
    name   = "isDefault"
    values = ["true"]
  }
}

# A `check` block reports a failure as a warning, not an error, so this does
# not block an apply. That is the right severity: the finding is drift, the
# remediation is a separate imperative command, and wedging every unrelated
# apply behind a default VPC in ap-south-1 would just teach people to delete
# this block.
#
# `check` does not support for_each, hence the aggregate over the data sources
# above rather than one check per region.
check "no_default_vpcs" {
  assert {
    condition = alltrue([
      for vpcs in data.aws_vpcs.default : length(vpcs.ids) == 0
    ])
    error_message = format(
      "Default VPC present in: %s. Run `just apply` to delete them.",
      join(", ", sort([
        for region, vpcs in data.aws_vpcs.default : region
        if length(vpcs.ids) > 0
      ]))
    )
  }
}
