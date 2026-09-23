import concurrent.futures
import datetime
import socket
import ssl
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from verification.common import Rejected
from verification.relay import pump, serve, tunnel_socket


class RelayTests(unittest.TestCase):
    def test_bidirectional_bytes_and_half_close(self):
        client, left = socket.socketpair()
        right, server = socket.socketpair()
        with client, left, right, server, concurrent.futures.ThreadPoolExecutor() as pool:
            client.settimeout(2)
            server.settimeout(2)
            result = pool.submit(pump, left, right, seconds=2)
            client.sendall(b'opaque-client-bytes')
            client.shutdown(socket.SHUT_WR)
            self.assertEqual(server.recv(100), b'opaque-client-bytes')
            self.assertEqual(server.recv(100), b'')
            server.sendall(b'opaque-server-bytes')
            server.shutdown(socket.SHUT_WR)
            self.assertEqual(client.recv(100), b'opaque-server-bytes')
            self.assertEqual(client.recv(100), b'')
            result.result(timeout=3)

    def test_size_and_idle_deadline(self):
        for flood in (False, True):
            client, left = socket.socketpair()
            right, server = socket.socketpair()
            with client, left, right, server:
                if flood:
                    client.sendall(b'x' * 33)
                with self.assertRaisesRegex(Rejected, 'relay_size' if flood else 'relay_timeout'):
                    pump(left, right, seconds=0.05, maximum=32)

    def test_disabled_policy_never_opens_listener(self):
        with patch('verification.relay.socket.socket') as create:
            with self.assertRaisesRegex(Rejected, 'source_policy_not_approved'):
                serve(16)
            create.assert_not_called()

    def test_tunnel_uses_fixed_parent_cid_and_port(self):
        with patch('verification.relay.socket.socket') as create, \
                patch('verification.relay.socket.AF_VSOCK', 40, create=True):
            tunnel_socket('bank.example')
            create.return_value.connect.assert_called_once_with((2, 5001))
        with self.assertRaisesRegex(Rejected, 'destination_forbidden'):
            tunnel_socket('bank.example', 80)

    def test_tls_crosses_relay_without_parent_termination(self):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'bank.invalid')])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(minutes=1))
                .not_valid_after(now + datetime.timedelta(minutes=5))
                .add_extension(x509.SubjectAlternativeName([x509.DNSName('bank.invalid')]), False)
                .sign(key, hashes.SHA256()))
        with tempfile.TemporaryDirectory() as directory:
            cert_path, key_path = Path(directory) / 'cert.pem', Path(directory) / 'key.pem'
            cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
            key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                 serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
            client_ctx = ssl.create_default_context(cafile=str(cert_path))
            server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            server_ctx.load_cert_chain(cert_path, key_path)
            client, left = socket.socketpair()
            right, server = socket.socketpair()
            def bank():
                with server_ctx.wrap_socket(server, server_side=True) as secure:
                    self.assertEqual(secure.recv(100), b'synthetic-session')
                    secure.sendall(b'synthetic-bank-response')
            with client, left, right, server, concurrent.futures.ThreadPoolExecutor() as pool:
                client.settimeout(2)
                server.settimeout(2)
                relay = pool.submit(pump, left, right, seconds=2)
                bank_result = pool.submit(bank)
                with client_ctx.wrap_socket(client, server_hostname='bank.invalid') as secure:
                    secure.sendall(b'synthetic-session')
                    self.assertEqual(secure.recv(100), b'synthetic-bank-response')
                bank_result.result(timeout=3)
                relay.result(timeout=3)
