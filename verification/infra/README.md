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

For non-interactive SSM builds, set `NITRO_CLI_ARTIFACTS` to a dedicated writable
build directory. Nitro bootstrap does not preserve Docker PATH/WORKDIR assumptions:
the image uses an absolute Python executable and `verification/boot.py` to resolve
its package location. Do not add debug mode to a release test; debug measurements
must be rejected. Debug console diagnosis is limited to disposable images without secrets.

Record instance ID, source/archive digest, enclave image measurements, test results,
actual lifecycle and conservative cost. Keep account-specific coordinates under ignored
`.local/verification/`, not in contributor instructions.

Rollback/cleanup: stop accepting attempts; terminate the pilot enclave, delete the
owning CloudFormation stack, verify the instance is terminated and its volume deleted.
Preserve public build evidence and private cost accounting. Never delete unrelated
instances, roles, images, log groups or keys by a name-prefix guess.

## Bank egress relay (not yet hardware validated)

After source-policy approval, install the same reviewed source policy on the parent
and in the measured enclave image. Run `python -m verification.relay --enclave-cid
<verified-cid>` on the parent using the actual enclave CID from the current launch.
The relay binds vsock port 5001, checks the peer CID and has no TCP listener. Do not
add a caller-selected hostname, port, HTTP proxy or host-side TLS termination.
Select `transport="nitro"` in the trusted enclave acquisition call. Bank credentials
never belong on the parent. Restart/review the relay when the enclave CID changes.

Keep the pilot lifetime guard and budget reservation in force. Relay time/byte/rate
limits are per process, not a substitute for persistent controller admission. Test
real vsock TLS, wrong CID, stalled DNS and certificate rejection on the disposable
pilot before calling this transport hardware verified. The checked-in source policy
is disabled, so the relay intentionally refuses to start.

## Rebuild comparison

Use the same immutable base digest, exact source archive and pinned Nitro toolchain.
Build twice with `docker build --no-cache`, then run `nitro-cli build-enclave` for
each image. Compare every PCR measurement and separately compare complete EIF
SHA-384 hashes; neither comparison substitutes for the other. Run
`nitro-cli describe-eif --eif-path <image>` to inspect metadata differences.

The Dockerfile disables pip bytecode compilation and normalizes installation/source
mtimes. The [September 23 experiment](evidence/2026-09-23-nitro-reproducibility.json)
obtained matching PCR0/1/2 on one host, but different EIF hashes. Do not publish
these experimental measurements in `release.json`: independent reproduction,
byte-identical artifact handling and signed hardware validation remain unresolved.

CI now runs `build_measurements.sh` on two separate disposable Ubuntu runners and
compares source/toolchain/base pins and PCR0/1/2. The builder uses a digest-pinned
Amazon Linux container and Nitro CLI 1.5.0. Reports and installed package inventories
are retained seven days; unsigned EIF files are not published as releases. Complete
EIF hashes are reported separately and may differ due to metadata. This workflow
must pass before independent-runner measurement agreement is claimed.

The builder container controls the runner's Docker socket. Run this script only on
a disposable, credential-free Linux build host, never alongside production containers
or bank sessions. It neither starts an enclave nor provisions AWS. Matching CI
measurements do not establish hardware attestation, PCR8 signing or release approval.
