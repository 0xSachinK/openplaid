"""Install the hash-pinned public compiler for credential-free adapter builds."""
import gzip
import hashlib
import json
import platform
import urllib.request
from pathlib import Path

root = Path(__file__).resolve().parents[2]
manifest = json.loads((root / 'verification/infra/javy.json').read_text())
platforms = {('Darwin', 'arm64'): ('darwin-arm64', 'arm-macos'),
             ('Linux', 'x86_64'): ('linux-x64', 'x86_64-linux')}
key, archive_platform = platforms[(platform.system(), platform.machine())]
pin = manifest['binaries'][key]
output = root / '.local/verification/javy'
if output.exists():
    if hashlib.sha256(output.read_bytes()).hexdigest() != pin['binarySha256']:
        raise SystemExit('Existing compiler differs from the pin; refusing to overwrite it')
else:
    url = f"https://github.com/bytecodealliance/javy/releases/download/v{manifest['version']}/javy-{archive_platform}-v{manifest['version']}.gz"
    with urllib.request.urlopen(url, timeout=30) as response:
        archive = response.read(64 * 1024 * 1024 + 1)
    if hashlib.sha256(archive).hexdigest() != pin['archiveSha256']:
        raise SystemExit('Compiler archive hash mismatch')
    binary = gzip.decompress(archive)
    if hashlib.sha256(binary).hexdigest() != pin['binarySha256']:
        raise SystemExit('Compiler executable hash mismatch')
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open('xb') as stream:
        stream.write(binary)
    output.chmod(0o700)
print('Pinned Javy compiler ready')
