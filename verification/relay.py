"""Fixed-destination, ciphertext-only parent relay for one admitted Nitro enclave.

No destination negotiation, TLS termination, HTTP parsing, credentials or logs.
Each connection gets a killable worker so OS DNS cannot block the listener forever.
"""
import argparse
import errno
import select
import socket
import subprocess
import sys
import time
from pathlib import Path

from .acquisition import checked_origin, public_socket
from .common import require, strict_json

PORT = 5001
MAX_BYTES = 2 * 1024 * 1024
BUFFER_BYTES = 65536


def tunnel_socket(host, port=443):
    """Enclave-side socket factory. TLS remains in acquisition.fetch_source."""
    checked_origin('https://' + host)
    require(port == 443, 'destination_forbidden')
    stream = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    stream.settimeout(10)
    try:
        stream.connect((2, PORT))  # Nitro parent CID, fixed bank relay port.
        return stream
    except BaseException:
        stream.close()
        raise


def pump(left, right, *, seconds=15, maximum=MAX_BYTES):
    """Bound both directions, buffering and wall time, including half-closed peers."""
    streams = (left, right)
    buffers = [bytearray(), bytearray()]  # Bytes waiting to be written to each socket.
    totals = [0, 0]
    ended = [False, False]
    shut = [False, False]
    end = time.monotonic() + seconds
    for stream in streams:
        stream.setblocking(False)
    while True:
        for i in range(2):
            if ended[1 - i] and not buffers[i] and not shut[i]:
                try:
                    streams[i].shutdown(socket.SHUT_WR)
                except OSError as error:
                    if error.errno not in (errno.ENOTCONN, errno.EPIPE):
                        raise
                shut[i] = True
        if all(ended) and not any(buffers):
            return
        remaining = end - time.monotonic()
        require(remaining > 0, 'relay_timeout')
        reads = [streams[i] for i in range(2) if not ended[i] and len(buffers[1-i]) < BUFFER_BYTES]
        writes = [streams[i] for i in range(2) if buffers[i]]
        readable, writable, _ = select.select(reads, writes, [], remaining)
        for stream in readable:
            i = streams.index(stream)
            try:
                data = stream.recv(min(16384, BUFFER_BYTES - len(buffers[1-i])))
            except BlockingIOError:
                continue
            if not data:
                ended[i] = True
                continue
            totals[i] += len(data)
            require(totals[i] <= maximum, 'relay_size')
            buffers[1-i].extend(data)
        for stream in writable:
            i = streams.index(stream)
            try:
                sent = stream.send(buffers[i])
            except BlockingIOError:
                continue
            require(sent > 0, 'relay_closed')
            del buffers[i][:sent]


def worker(fd):
    # Policy is installed with reviewed code; never supplied by the connection.
    policy = strict_json((Path(__file__).parent / 'policies/mercury.json').read_bytes())
    require(policy.get('enabled') is True and policy.get('status') == 'approved',
            'source_policy_not_approved')
    require(len(policy.get('origins', [])) == 1, 'unsupported_policy')
    host = checked_origin(policy['origins'][0])
    with socket.socket(fileno=fd) as incoming, public_socket(host, 443) as upstream:
        pump(incoming, upstream)


def serve(enclave_cid):
    require(type(enclave_cid) is int and 4 <= enclave_cid < 2**32 - 1, 'invalid_enclave_cid')
    # Refuse startup before an operator approves the fixed bank destination.
    policy = strict_json((Path(__file__).parent / 'policies/mercury.json').read_bytes())
    require(policy.get('enabled') is True and policy.get('status') == 'approved' and
            len(policy.get('origins', [])) == 1, 'source_policy_not_approved')
    checked_origin(policy['origins'][0])
    with socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM) as listener:
        listener.bind((socket.VMADDR_CID_ANY, PORT))
        listener.listen(4)
        window, calls = time.monotonic(), 0
        while True:
            incoming, peer = listener.accept()
            with incoming:
                if peer[0] != enclave_cid:
                    continue
                if time.monotonic() - window >= 60:
                    window, calls = time.monotonic(), 0
                if calls >= 6:
                    continue
                calls += 1
                try:
                    subprocess.run([sys.executable, '-I', str(Path(__file__).with_name('relay_worker.py')),
                                    str(incoming.fileno())], pass_fds=(incoming.fileno(),),
                                   stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL, env={}, timeout=20, check=False)
                except subprocess.TimeoutExpired:
                    pass  # run() kills/reaps the resolver/pump process. Never retry.


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--enclave-cid', type=int, required=True)
    serve(parser.parse_args().enclave_cid)
