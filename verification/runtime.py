"""Pilot enclave entrypoint. Attestation available; live sessions fail closed until released.

No network on import. No shell execution, dynamic imports, or contributor adapter loading.
The pilot exposes no model credentials, signing authority or bank acquisition operation.
"""
import socket
import struct
import time
from pathlib import Path

from .attestation import policy_digest
from .channel import SessionChannel
from .common import Rejected, b64, canonical, fields, require, strict_json, unb64
from .nsm import attest

HERE = Path(__file__).parent


def receive(stream, maximum=32768):
    deadline = time.monotonic() + 5
    def exact(length):
        parts = bytearray()
        while len(parts) < length:
            remaining = deadline - time.monotonic()
            require(remaining > 0, "frame_timeout")
            stream.settimeout(remaining)
            piece = stream.recv(length - len(parts))
            require(bool(piece), "truncated_frame")
            parts.extend(piece)
        return bytes(parts)
    size = struct.unpack("!I", exact(4))[0]
    require(0 < size <= maximum, "frame_size")
    return strict_json(exact(size), maximum)


def send(stream, value):
    body = canonical(value)
    require(len(body) <= 65536, "response_size")
    stream.sendall(struct.pack("!I", len(body)) + body)


class Runtime:
    def __init__(self):
        self.channel = SessionChannel()
        policy = strict_json((HERE / "policies/service.json").read_bytes())
        source = strict_json((HERE / "policies/mercury.json").read_bytes())
        model = strict_json((HERE / "policies/model-trust.json").read_bytes())
        operator = strict_json((HERE / "policies/operator-trust.json").read_bytes())
        prompt = (HERE / "prompts/payment-review-v1.txt").read_text()
        self.policy_digest = policy_digest(policy, prompt, source, model, operator)
        self.window = time.monotonic()
        self.calls = 0

    def handle(self, request):
        require(isinstance(request, dict), "invalid_request")
        if request.get("operation") == "status":
            fields(request, ("operation",))
            return {"schemaVersion": "1", "mode": "pilot", "liveVerification": False,
                    "policyDigest": self.policy_digest, "scheduledJudgment": False}
        if request.get("operation") == "attest":
            fields(request, ("operation", "nonce"))
            if time.monotonic() - self.window > 60:
                self.window, self.calls = time.monotonic(), 0
            require(self.calls < 10, "rate_limited")
            self.calls += 1
            nonce = unb64(request["nonce"], 32)
            require(len(nonce) == 32, "nonce_size")
            document = attest(nonce, self.channel.public_key_der, bytes.fromhex(self.policy_digest))
            return {"attestation": b64(document), "publicKey": b64(self.channel.public_key_der),
                    "policyDigest": self.policy_digest}
        # No dormant 'debug', echo, arbitrary fetch, prompt or decrypt route.
        raise Rejected("live_verification_unavailable")


def main():
    runtime = Runtime()
    listener = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    listener.bind((socket.VMADDR_CID_ANY, 5000))
    listener.listen(8)
    while True:
        stream, _ = listener.accept()
        with stream:
            stream.settimeout(5)
            try:
                result = runtime.handle(receive(stream))
            except Rejected as error:
                result = {"error": str(error)}
            except Exception:
                result = {"error": "request_failed"}
            try:
                send(stream, result)
            except OSError:
                pass


if __name__ == "__main__":
    main()
