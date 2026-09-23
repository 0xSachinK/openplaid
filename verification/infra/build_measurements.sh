#!/usr/bin/env bash
# Credential-free build only. Run on a disposable Linux x86_64 host with Docker.
set -euo pipefail
umask 077
root=$(git rev-parse --show-toplevel)
cd "$root"
revision=$(git rev-parse HEAD)
out="$root/.local/nitro-build"
mkdir -p "$out"
# Same immutable Python image used by the hardware pilot.
base='python@sha256:4b4c524dc3dce996864e030c7bd9c6b0e517597189fee48f48e05b499442444b'
builder='amazonlinux@sha256:bc20ab39b3e976096f7e5782e9457eb5144810a3cbdbfdbe111d1b31b82f47b4'
docker build --no-cache --build-arg "BASE_IMAGE=$base" -f verification/infra/Dockerfile -t openplaid-ci:eif .
# The socket grants control of this disposable build host. Never run on a host
# containing credentials, bank sessions, production containers or signing keys.
docker run --rm --platform linux/amd64 -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$out:/output" "$builder" bash -euc '
    dnf install -y aws-nitro-enclaves-cli-1.5.0 aws-nitro-enclaves-cli-devel-1.5.0 docker
    test "$(nitro-cli --version)" = "Nitro CLI 1.5.0"
    export NITRO_CLI_ARTIFACTS=/tmp/nitro-artifacts
    mkdir -p "$NITRO_CLI_ARTIFACTS"
    nitro-cli build-enclave --docker-uri openplaid-ci:eif --output-file /output/image.eif > /output/measurements.json
    rpm -qa | sort > /output/builder-packages.txt
  '
sudo chown -R "$(id -u):$(id -g)" "$out"
python3 - "$revision" "$base" "$builder" "$out" <<'PY'
import hashlib,json,sys
from pathlib import Path
revision,base,builder,directory=sys.argv[1:]
p=Path(directory)
m=json.loads((p/'measurements.json').read_text())['Measurements']
assert set(m)=={'HashAlgorithm','PCR0','PCR1','PCR2'}
result={'sourceCommit':revision,'baseImage':base,'builderImage':builder,'nitroCliVersion':'1.5.0',
        'measurements':m,'eifSha384':hashlib.file_digest((p/'image.eif').open('rb'),'sha384').hexdigest(),
        'signed':False,'hardwareAttested':False,'liveVerification':False}
(p/'build-report.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result))
PY
