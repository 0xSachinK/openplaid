"""Small shared protocol primitives. Error codes never contain submitted data."""
import base64
import hashlib
import json
import math
import re


class Rejected(ValueError):
    pass


def require(condition, code):
    if not condition:
        raise Rejected(code)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def strict_json(raw, maximum=65536):
    require(isinstance(raw, (bytes, str)) and len(raw) <= maximum, "input_size")

    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate_key")
            result[key] = value
        return result

    def bad_constant(_):
        raise Rejected("invalid_number")

    def finite_number(value):
        parsed = float(value)
        require(math.isfinite(parsed), "invalid_number")
        return parsed

    try:
        if isinstance(raw, str):
            require(len(raw.encode("utf-8")) <= maximum, "input_size")
        return json.loads(raw, object_pairs_hook=pairs, parse_constant=bad_constant,
                          parse_float=finite_number)
    except (ValueError, RecursionError, UnicodeError) as error:
        raise Rejected("invalid_json") from error


def fields(value, names):
    require(isinstance(value, dict) and set(value) == set(names), "invalid_fields")


def identifier(value):
    require(isinstance(value, str) and re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_./-]{0,119}", value),
            "invalid_identifier")
    return value


def hex_digest(value):
    require(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value), "invalid_digest")
    return value


def b64(value):
    return base64.b64encode(value).decode("ascii")


def unb64(value, maximum=65536):
    require(isinstance(value, str) and len(value) <= maximum * 2, "invalid_encoding")
    try:
        result = base64.b64decode(value, validate=True)
        require(len(result) <= maximum, "input_size")
        return result
    except (ValueError, TypeError) as error:
        raise Rejected("invalid_encoding") from error
