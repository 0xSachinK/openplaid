"""Read-only, credential-free release readiness report for people and agents.

This is a checklist, not an approval oracle. Passing configuration checks cannot
enable the runtime: unavailable integrations remain explicit code-level blockers.
"""
import json
import time
from pathlib import Path

from .attestation import policy_digest
from .common import strict_json

HERE = Path(__file__).parent


def inspect(directory=HERE):
    load = lambda name: strict_json((directory / name).read_bytes())
    service = load("policies/service.json")
    source = load("policies/mercury.json")
    model = load("policies/model-trust.json")
    operator = load("policies/operator-trust.json")
    release = load("release.json")
    prompt = (directory / "prompts/payment-review-v1.txt").read_text()
    policy = policy_digest(service, prompt, source, model, operator)
    checks = {
        "publicReleaseApproved": release.get("status") == "approved",
        "releaseUnexpired": release.get("expiresAt", 0) > time.time(),
        "liveReleaseEnabled": release.get("liveVerification") is True,
        "policyMatchesRelease": release.get("policyDigest") == policy,
        "exactMeasurementsPublished": set(release.get("measurements", {})) == {"0", "1", "2", "8"},
        "sourcePolicyApproved": source.get("enabled") is True and source.get("status") == "approved",
        "modelTrustApproved": model.get("enabled") is True and model.get("status") == "approved",
        "operatorKeyProvisioned": operator.get("enabled") is True and bool(operator.get("permitPublicKey")),
        # Remove each blocker only alongside the implementation and independent tests.
        "independentBankOracleIntegrated": False,
        "contributorSandboxIntegrated": False,
        "veniceCpuGpuAttestationIntegrated": False,
        "signedReceiptsIntegrated": False,
        "liveRuntimeIntegrated": False,
        "hardwareEndToEndVerified": False,
    }
    return {"schemaVersion": "1", "readyForSecrets": all(checks.values()),
            "policyDigest": policy, "checks": checks,
            "blockers": [name for name, passed in checks.items() if not passed],
            "scheduledJudgment": False, "automaticPayout": False}


if __name__ == "__main__":
    result = inspect()
    print(json.dumps(result, sort_keys=True))
    raise SystemExit(0 if result["readyForSecrets"] else 2)
