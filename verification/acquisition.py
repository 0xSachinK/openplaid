"""Policy-constructed, size-bounded bank reads. TLS terminates in this process.

The socket factory is selected at process startup, never supplied by a request.
In Nitro it must be the vsock tunnel to the fixed-destination parent relay.
"""
import http.client
import ipaddress
import re
import socket
import ssl
import threading
import time
from urllib.parse import urlsplit

from .common import Rejected, fields, require, strict_json


class ReadDeadline:
    """Close the active socket at an absolute deadline, including slow TLS/headers.

    A blocking OS DNS lookup is not interruptible here. Production must use the
    fixed-destination relay with its own bounded resolver and process watchdog.
    No credentials are sent if resolution returns after this deadline.
    """
    def __init__(self, seconds=15):
        self.end = time.monotonic() + seconds
        self.lock = threading.Lock()
        self.stream = None
        self.expired = False
        self.timer = threading.Timer(seconds, self.expire)
        self.timer.daemon = True
        self.timer.start()

    def expire(self):
        with self.lock:
            self.expired = True
            if self.stream is not None:
                try:
                    self.stream.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                self.stream.close()

    def tls(self, raw, host):
        with self.lock:
            if self.expired or time.monotonic() >= self.end:
                raw.close()
                raise Rejected("bank_read_timeout")
            self.stream = raw
            wrapped = ssl.create_default_context().wrap_socket(
                raw, server_hostname=host, do_handshake_on_connect=False)
            self.stream = wrapped
            wrapped.settimeout(max(0.001, self.end - time.monotonic()))
        wrapped.do_handshake()
        return wrapped

    def check(self):
        require(not self.expired and time.monotonic() < self.end, "bank_read_timeout")

    def close(self):
        self.timer.cancel()
        self.expire()


def checked_origin(origin):
    require(isinstance(origin, str), "invalid_origin")
    url = urlsplit(origin)
    require(url.scheme == "https" and url.port in (None, 443) and
            url.path in ("", "/") and not url.query and not url.fragment and
            not url.username and not url.password, "invalid_origin")
    host = url.hostname
    require(host is not None and host == host.lower() and not host.endswith(".") and
            re.fullmatch(r"[a-z0-9]+(?:[a-z0-9.-]*[a-z0-9])?", host) and
            ".." not in host and "." in host, "invalid_origin")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return host
    raise Rejected("ip_literal_forbidden")


def public_socket(host, port=443):
    """Resolve once, reject all non-public answers, connect to the checked address."""
    answers = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    require(0 < len(answers) <= 32, "dns_failed")
    for _, _, _, _, address in answers:
        ip = ipaddress.ip_address(address[0])
        require(ip.is_global and not ip.is_multicast and not ip.is_reserved,
                "destination_forbidden")
    last = None
    for family, socktype, proto, _, address in answers:
        stream = socket.socket(family, socktype, proto)
        stream.settimeout(10)
        try:
            stream.connect(address)
            return stream
        except OSError as error:
            stream.close()
            last = error
    raise Rejected("connection_failed") from last


def fetch_source(policy, credentials, *, socket_factory=public_socket):
    require(policy.get("enabled") is True and policy.get("status") == "approved",
            "source_policy_not_approved")
    require(len(policy.get("origins", [])) == 1 and len(policy.get("operations", [])) == 1,
            "unsupported_policy")
    host = checked_origin(policy["origins"][0])
    operation = policy["operations"][0]
    fields(operation, ("id", "method", "path", "credentialHeaders"))
    require(operation["method"] == "GET", "operation_forbidden")
    path = operation["path"]
    require(isinstance(path, str) and path.startswith("/") and not path.startswith("//") and
            len(path) <= 2048 and all(33 <= ord(c) <= 126 for c in path) and
            "#" not in path and "\\" not in path, "operation_forbidden")
    names = operation["credentialHeaders"]
    require(isinstance(names, list) and 1 <= len(names) <= 4 and len(names) == len(set(names)) and
            all(isinstance(n, str) and re.fullmatch(r"[a-z][a-z0-9-]{0,63}", n) and
                n not in {"host", "connection", "content-length", "transfer-encoding", "accept-encoding"}
                for n in names), "invalid_credential_policy")
    fields(credentials, names)
    require(all(isinstance(v, str) and 0 < len(v) <= 8192 and
                all(32 <= ord(c) <= 126 for c in v) for v in credentials.values()), "invalid_session")
    headers = {**credentials, "Accept": "application/json", "Accept-Encoding": "identity",
               "Connection": "close"}
    connection = http.client.HTTPSConnection(host, timeout=10)
    deadline = ReadDeadline()
    try:
        # No URL redirects, proxy environment, cookies from responses or caller-provided URLs.
        raw = socket_factory(host, 443)
        try:
            connection.sock = deadline.tls(raw, host)
        except Exception:
            raw.close()
            raise
        deadline.check()
        connection.request("GET", path, headers=headers)
        response = connection.getresponse()
        require(response.status == 200, "bank_read_failed")
        require(response.getheader("Content-Encoding", "identity") == "identity", "compressed_response")
        require(response.getheader("Content-Type", "").split(";", 1)[0].strip() == "application/json",
                "invalid_content_type")
        body = response.read(1048577)
        deadline.check()
        require(len(body) <= 1048576, "bank_response_size")
        return strict_json(body, 1048576)
    except Rejected:
        raise
    except Exception as error:
        raise Rejected("bank_read_failed") from error
    finally:
        deadline.close()
        connection.close()
