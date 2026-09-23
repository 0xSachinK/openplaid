# Isolated Nitro pilot runbook

Owner: OpenPlaid. Environment: pilot. Scope: a new tagged Nitro build/test host only.
The deployer must supply and verify its AWS account, profile, region, VPC and subnet.
Never reuse an existing payment attestor, its keys, or its bank sessions.

Before provisioning:

1. Record caller identity, region, exact source commit and local tests. Confirm no
   existing OpenPlaid pilot is running. Verify the subnet belongs to the specified VPC.
2. Estimate c6i.xlarge instance, 24 GB gp3 volume, public IPv4 and transfer charges.
   Reserve a conservative upper bound in `verification.cli reserve-expense` within
   the task's $50 cap. AWS credits do not increase the authorized spending limit.
3. Validate `pilot.cfn.json`. Inspect IAM and network changes. The role has SSM
   management access only; no production secrets or application data permissions.
4. Deploy one named stack with explicit account/profile/region and project tags.
   No inbound ports are allowed. Use Systems Manager to build and test.

The host is configured to shut down after 110 minutes and terminate on shutdown;
its root volume is deleted. This is a one-time resource-lifetime guard, not an agent
judgment schedule. Confirm that shutdown is actually scheduled before starting work.
If bootstrap fails, terminate through the owning stack. Do not leave a failed build
host running. External operator cleanup remains required; this timer is not a formal
guarantee against arbitrary provider billing.

Build the enclave from the exact source archive and pinned dependencies. Do not put
API keys or sessions in image layers, Docker arguments, SSM commands or user-data.
Publish a release only after independent rebuilds agree, real Nitro attestation is
verified, negative security tests pass, and policy/consent bindings are checked.
Never fill `release.json` with example measurements and call it approved.

Record instance ID, source/archive digest, enclave image measurements, test results,
actual lifecycle and conservative cost. Keep account-specific coordinates under ignored
`.local/verification/`, not in contributor instructions.

Rollback/cleanup: stop accepting attempts; terminate the pilot enclave, delete the
owning CloudFormation stack, verify the instance is terminated and its volume deleted.
Preserve public build evidence and private cost accounting. Never delete unrelated
instances, roles, images, log groups or keys by a name-prefix guess.
