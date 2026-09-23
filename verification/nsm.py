"""Minimal Linux NSM ioctl binding to the public AWS NSM wire protocol.

Protocol reference: aws/aws-nitro-enclaves-nsm-api (Apache-2.0), driver and api modules.
This module is an original Python binding, not copied application code.
"""
import ctypes
import fcntl
import os
import platform

import cbor2

from .common import Rejected, require


def attest(nonce, public_key, policy_digest):
    require(platform.system() == "Linux" and platform.machine() == "x86_64", "nsm_platform")
    require(isinstance(nonce, bytes) and len(nonce) == 32, "nonce_size")
    require(isinstance(public_key, bytes) and len(public_key) <= 1024, "invalid_public_key")
    require(isinstance(policy_digest, bytes) and len(policy_digest) == 32, "invalid_policy_digest")
    request = cbor2.dumps({"Attestation": {"nonce": nonce, "public_key": public_key,
                                          "user_data": policy_digest}})
    require(len(request) <= 4096, "nsm_request_size")
    source = ctypes.create_string_buffer(request)
    target = ctypes.create_string_buffer(12288)
    # nsm.h: two iovecs, each a 64-bit address followed by a 64-bit length.
    message = bytearray(bytes((ctypes.c_uint64 * 4)(
        ctypes.addressof(source), len(request), ctypes.addressof(target), len(target))))
    try:
        fd = os.open("/dev/nsm", os.O_RDWR | os.O_CLOEXEC)
        try:
            fcntl.ioctl(fd, 0xC0200A00, message, True)
        finally:
            os.close(fd)
        length = (ctypes.c_uint64 * 4).from_buffer_copy(message)[3]
        require(0 < length <= 12288, "nsm_response_size")
        result = cbor2.loads(target.raw[:length])
        document = result["Attestation"]["document"]
        require(isinstance(document, bytes) and len(document) <= 12288, "invalid_nsm_response")
        return document
    except Rejected:
        raise
    except Exception as error:
        raise Rejected("nsm_unavailable") from error
