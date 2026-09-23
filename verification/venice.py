"""Venice E2EE primitives and closed request construction.

Live dispatch is forbidden until the model's CPU/GPU evidence and release identity
have been independently verified. Never accept the API's verified=true alone.
"""
import secrets

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .common import Rejected, canonical, fields, require, strict_json
from .evaluation import ROLES


def transport_key(shared):
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=b"ecdsa_encryption").derive(shared)


def public_bytes(key):
    return key.public_key().public_bytes(serialization.Encoding.X962,
                                         serialization.PublicFormat.UncompressedPoint)


def encrypt_message(text, verified_key):
    """Caller must authenticate the key independently before invoking this primitive."""
    require(isinstance(text, str) and len(text.encode()) <= 24000, "model_input_size")
    peer = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), verified_key)
    ephemeral = ec.generate_private_key(ec.SECP256K1())
    aes_key = transport_key(ephemeral.exchange(ec.ECDH(), peer))
    nonce = secrets.token_bytes(12)
    encrypted = AESGCM(aes_key).encrypt(nonce, text.encode(), None)
    return (public_bytes(ephemeral) + nonce + encrypted).hex()


def decrypt_chunk(value, client_key):
    require(isinstance(value, str) and len(value) <= 16384 and len(value) % 2 == 0,
            "model_output_size")
    try:
        raw = bytes.fromhex(value)
        require(len(raw) >= 93 and raw[0] == 4, "invalid_model_ciphertext")
        peer = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), raw[:65])
        key = transport_key(client_key.exchange(ec.ECDH(), peer))
        plain = AESGCM(key).decrypt(raw[65:77], raw[77:], None)
        require(len(plain) <= 4096, "model_output_size")
        return plain.decode("utf-8")
    except Exception as error:
        raise Rejected("invalid_model_ciphertext") from error


def projection(candidates):
    """Only approved field/value candidates reach inference; never headers, full HARs or memos.

    Caller supplies candidates from reviewed source-field extraction, not arbitrary JSON.
    """
    fields(candidates, ROLES)
    for role in ROLES:
        require(isinstance(candidates[role], dict) and 1 <= len(candidates[role]) <= 8,
                "invalid_candidates")
        for ref, candidate in candidates[role].items():
            require(isinstance(ref, str) and len(ref) <= 80 and ref.isascii() and
                    all(c.isalnum() or c in "-_/." for c in ref), "invalid_reference")
            fields(candidate, ("value", "transaction"))
            require(all(isinstance(v, str) and len(v) <= 256 for v in candidate.values()),
                    "invalid_candidate_value")
    encoded = canonical(candidates)
    require(len(encoded) <= 20000, "model_input_size")
    return encoded.decode()


def request_body(*, model, prompt, candidates, verified_key):
    require(isinstance(model, str) and model.startswith("e2ee-") and len(model) <= 100,
            "unapproved_model")
    require(len(prompt.encode()) <= 4000, "prompt_size")
    return {"model": model, "stream": True, "max_tokens": 512,
            "messages": [{"role": "system", "content": encrypt_message(prompt, verified_key)},
                         {"role": "user", "content": encrypt_message(projection(candidates), verified_key)}],
            "venice_parameters": {"include_venice_system_prompt": False, "enable_web_search": "off"}}


def decode_stream(lines, client_key):
    """Bounded SSE decoding; fail closed on truncation, repeated chunks or plaintext fallback."""
    output = []
    seen = set()
    total = 0
    wire_size = 0
    completed = False
    for line in lines:
        wire_size += len(line)
        require(wire_size <= 131072, "model_output_size")
        if not line.strip():
            continue
        require(line.startswith(b"data: "), "invalid_model_stream")
        data = line[6:].strip()
        if data == b"[DONE]":
            completed = True
            break
        chunk = strict_json(data, 32768)
        require(isinstance(chunk, dict) and "error" not in chunk, "model_failed")
        choices = chunk.get("choices")
        require(isinstance(choices, list) and len(choices) <= 1, "invalid_model_stream")
        if not choices:
            continue
        choice = choices[0]
        require(choice.get("index") == 0 and isinstance(choice.get("delta"), dict), "invalid_model_stream")
        delta = choice["delta"]
        require(not delta.get("tool_calls") and not delta.get("function_call") and
                not delta.get("reasoning_content"), "unexpected_model_output")
        content = delta.get("content")
        if content:
            require(content not in seen, "replayed_model_chunk")
            seen.add(content)
            plain = decrypt_chunk(content, client_key)
            total += len(plain.encode())
            require(total <= 4096, "model_output_size")
            output.append(plain)
        require(choice.get("finish_reason") not in ("length", "tool_calls", "content_filter"),
                "incomplete_model_output")
    require(completed and output, "incomplete_model_output")
    return "".join(output)
