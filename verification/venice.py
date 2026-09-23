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
    """Decode a bounded complete SSE response, discarding encrypted reasoning.

    Decryption alone is not provider authentication. The caller must independently
    authenticate the exact request and complete wire response before using output.
    This primitive does not authorize private-data dispatch or model judgments.
    """
    output = []
    seen = set()
    total = 0
    wire_size = 0
    count = 0
    line_count = 0
    completed = False
    stopped = False
    completion_id = None
    for line in lines:
        line_count += 1
        require(line_count <= 1024, "model_output_size")
        require(isinstance(line, bytes), "invalid_model_stream")
        wire_size += len(line)
        require(wire_size <= 131072, "model_output_size")
        if not line.strip():
            continue
        require(not completed and line.startswith(b"data: "), "invalid_model_stream")
        data = line[6:].strip()
        if data == b"[DONE]":
            require(stopped, "incomplete_model_output")
            completed = True
            continue
        count += 1
        require(count <= 512, "model_output_size")
        chunk = strict_json(data, 32768)
        require(isinstance(chunk, dict) and "error" not in chunk, "model_failed")
        current_id = chunk.get("id")
        require(isinstance(current_id, str) and 0 < len(current_id) <= 128 and
                current_id.isascii(), "invalid_model_stream")
        if completion_id is None:
            completion_id = current_id
        require(current_id == completion_id, "mixed_model_stream")
        choices = chunk.get("choices")
        require(isinstance(choices, list) and len(choices) <= 1, "invalid_model_stream")
        if not choices:
            # Usage metadata is not model output, authority or trusted billing.
            require(stopped, "invalid_model_stream")
            continue
        require(not stopped, "invalid_model_stream")
        choice = choices[0]
        require(isinstance(choice, dict) and type(choice.get("index")) is int and
                choice["index"] == 0 and isinstance(choice.get("delta"), dict), "invalid_model_stream")
        delta = choice["delta"]
        require(set(delta) <= {"content", "reasoning_content", "role"} and
                delta.get("role", "assistant") == "assistant", "unexpected_model_output")
        for field in ("content", "reasoning_content"):
            content = delta.get(field)
            require(content is None or isinstance(content, str), "unexpected_model_output")
            if not content:
                continue
            require(content not in seen, "replayed_model_chunk")
            seen.add(content)
            plain = decrypt_chunk(content, client_key)
            # Count all plaintext, including reasoning we never return or log.
            total += len(plain.encode())
            require(total <= 4096, "model_output_size")
            if field == "content":
                output.append(plain)
        finish = choice.get("finish_reason")
        require(finish in (None, "stop"), "incomplete_model_output")
        stopped = finish == "stop"
    require(completed and stopped and output, "incomplete_model_output")
    return "".join(output)
