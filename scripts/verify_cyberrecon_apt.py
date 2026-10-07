#!/usr/bin/env python3
"""Verify signed Debian metadata and its complete index/package SHA256 chain."""
import argparse
from datetime import datetime, timedelta, timezone
from email.parser import Parser
from email.utils import parsedate_to_datetime
import gzip
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
from check_release_security import check_artifact, safe_name

LIMIT = 8 * 1024 * 1024


def fields(data):
    message = Parser().parsestr(data)
    if message.defects or len(message.keys()) != len(set(k.lower() for k in message.keys())):
        raise ValueError('Invalid or duplicate Debian metadata fields')
    return message


def regular_file(root, name):
    relative = safe_name(name)
    path = root.joinpath(*relative.parts)
    if not relative.parts or not path.is_file() or any(p.is_symlink() for p in [path, *path.parents] if p != root.parent):
        raise ValueError('Repository member must be a regular file without symlinks')
    return path


def bounded(path):
    if path.stat().st_size > LIMIT:
        raise ValueError('Repository metadata exceeds size bound')
    return path.read_bytes()


def signature(keyring, fingerprint, signature_path, output, data=None):
    with tempfile.TemporaryDirectory(prefix='cyberrecon-gpgv-') as home:
        argv = ['gpgv', '--homedir', home, '--status-fd', '1', '--keyring', str(keyring)]
        if output:
            argv += ['--output', str(output)]
        argv += [str(signature_path)]
        if data:
            argv += [str(data)]
        result = subprocess.run(argv, capture_output=True, text=True, timeout=30)
    valid = [line.split() for line in result.stdout.splitlines() if line.startswith('[GNUPG:] VALIDSIG ')]
    if result.returncode or len(valid) != 1 or fingerprint not in (valid[0][2], valid[0][-1]):
        raise ValueError('Repository signature failed or signer fingerprint does not match trusted pin')


def verify(directory, keyring, fingerprint, expected_version='0.2.0-5', production=False):
    if not re.fullmatch('[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64}', fingerprint):
        raise ValueError('An independently verified full fingerprint is required')
    root = Path(directory).absolute()
    if root.is_symlink():
        raise ValueError('Repository root cannot be a symlink')
    root = root.resolve()
    keyring = Path(keyring).resolve(strict=True)
    check_artifact(keyring)
    release_root = root / 'dists/stable'
    release = regular_file(root, 'dists/stable/Release')
    inline = regular_file(root, 'dists/stable/InRelease')
    detached = regular_file(root, 'dists/stable/Release.gpg')
    for path in (release, inline, detached):
        bounded(path)
    if not bounded(inline).startswith(b'-----BEGIN PGP SIGNED MESSAGE-----\n') or not bounded(inline).rstrip().endswith(b'-----END PGP SIGNATURE-----'):
        raise ValueError('Unexpected clear-signature framing or unsigned trailing content')
    with tempfile.TemporaryDirectory(prefix='cyberrecon-release-verify-') as temporary:
        plaintext = Path(temporary) / 'Release'
        signature(keyring, fingerprint.upper(), inline, plaintext)
        if plaintext.read_bytes() != release.read_bytes():
            raise ValueError('InRelease and Release contents differ')
    signature(keyring, fingerprint.upper(), detached, None, release)
    metadata = fields(bounded(release).decode('utf-8'))
    for key, value in {'Origin': 'CyberRecon', 'Suite': 'stable', 'Codename': 'stable',
                       'Components': 'main', 'Architectures': 'amd64'}.items():
        if metadata.get(key) != value:
            raise ValueError('Unexpected repository field: ' + key)
    if metadata.get('Label') not in ('CyberRecon', 'CyberRecon development') or (production and metadata.get('Label') != 'CyberRecon'):
        raise ValueError('Development/unknown repository is not production')
    try:
        date = parsedate_to_datetime(metadata['Date'])
        expiry = parsedate_to_datetime(metadata['Valid-Until'])
    except (TypeError, ValueError) as error:
        raise ValueError('Valid signed dates are required') from error
    now = datetime.now(timezone.utc)
    if date.tzinfo is None or expiry.tzinfo is None or date > now + timedelta(minutes=10) or expiry <= now or expiry <= date:
        raise ValueError('Expired or future repository metadata')
    hashed = set()
    for line in (metadata.get('SHA256') or '').splitlines():
        if not line.strip():
            continue
        digest, size, name = line.split()
        if not re.fullmatch('[a-f0-9]{64}', digest) or name in hashed:
            raise ValueError('Invalid/duplicate SHA256 entry')
        path = regular_file(release_root, name)
        data = bounded(path)
        if len(data) != int(size) or hashlib.sha256(data).hexdigest() != digest:
            raise ValueError('Index SHA256 or size mismatch')
        hashed.add(name)
    names = {'main/binary-amd64/Packages', 'main/binary-amd64/Packages.gz'}
    if not names <= hashed:
        raise ValueError('Required indexes missing from signed SHA256 metadata')
    packages = bounded(regular_file(release_root, 'main/binary-amd64/Packages'))
    with gzip.open(regular_file(release_root, 'main/binary-amd64/Packages.gz'), 'rb') as stream:
        compressed = stream.read(LIMIT + 1)
    if compressed != packages:
        raise ValueError('Packages.gz differs from Packages or exceeds bound')
    versions = set()
    seen = set()
    for block in packages.decode('utf-8').strip().split('\n\n'):
        entry = fields(block + '\n')
        if entry.get('Package') != 'cyberrecon' or entry.get('Architecture') not in ('amd64', 'all'):
            raise ValueError('Unexpected package identity/architecture')
        filename = entry.get('Filename', '')
        if not filename.startswith('pool/main/c/cyberrecon/') or filename in seen:
            raise ValueError('Unexpected/duplicate package path')
        seen.add(filename)
        path = regular_file(root, filename)
        digest = entry.get('SHA256', '')
        if not re.fullmatch('[a-f0-9]{64}', digest) or path.stat().st_size != int(entry.get('Size', '-1')) or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise ValueError('Package SHA256 or size mismatch')
        for key in ('Package', 'Version', 'Architecture', 'Depends', 'Maintainer'):
            actual = subprocess.check_output(['dpkg-deb', '-f', str(path), key], text=True, timeout=10).strip()
            if actual != entry.get(key):
                raise ValueError('Package control/index mismatch: ' + key)
        versions.add(entry['Version'])
        if production and (not re.fullmatch(r'[^<>\r\n]+ <[^<>\s@]+@[^<>\s@]+\.[^<>\s@]+>', entry.get('Maintainer', ''))
                           or 'invalid.example' in entry.get('Maintainer', '')):
            raise ValueError('Real production maintainer metadata required')
        check_artifact(path)
    if expected_version not in versions:
        raise ValueError('Expected candidate package version missing')
    for path in root.rglob('*'):
        if path.is_symlink():
            raise ValueError('Symlink in repository')
        if path.is_file():
            check_artifact(path)
    return {'status': 'PASS', 'channel': 'stable', 'component': 'main', 'architecture': 'amd64',
            'versions': sorted(versions), 'fingerprint': fingerprint.upper(),
            'mode': 'production metadata' if production else 'local metadata verification; public installation NOT TESTED'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('repository')
    parser.add_argument('--keyring', required=True)
    parser.add_argument('--fingerprint', required=True)
    parser.add_argument('--expected-version', default='0.2.0-5')
    parser.add_argument('--production', action='store_true')
    args = parser.parse_args()
    print(json.dumps(verify(args.repository, args.keyring, args.fingerprint, args.expected_version, args.production), indent=2))
