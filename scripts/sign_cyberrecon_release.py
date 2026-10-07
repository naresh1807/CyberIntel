#!/usr/bin/env python3
"""Protected-runner signing: key material stays outside source/artifacts."""
import argparse
import importlib.util
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
PRODUCTION_FINGERPRINT = 'F1C454E3BB40C77AB236828DCB222DFEAD382DFC'
PRODUCTION_IDENTITY = 'Thatikonda Naresh Goud <nareshthatikonda143@gmail.com>'


def normalize_fingerprint(value):
    value = re.sub(r'\s+', '', value).upper()
    if not re.fullmatch(r'[A-F0-9]{40}|[A-F0-9]{64}', value):
        raise ValueError('A complete signing fingerprint is required')
    return value


def inspect_imported_key(listing, configured_fingerprint):
    expected = normalize_fingerprint(configured_fingerprint)
    if expected != PRODUCTION_FINGERPRINT:
        raise ValueError('Configured fingerprint differs from the approved production identity')
    keys = []
    current = None
    identities = []
    for line in listing.splitlines():
        fields = line.split(':')
        if fields[0] in ('sec', 'ssb'):
            if len(fields) < 12:
                raise ValueError('Incomplete imported key metadata')
            current = {'kind': fields[0], 'validity': fields[1], 'algorithm': fields[3],
                       'expiry': fields[6], 'capabilities': fields[11],
                       'curve': fields[16] if len(fields) > 16 else '', 'fingerprint': ''}
            keys.append(current)
        elif fields[0] == 'fpr' and current is not None:
            if len(fields) <= 9:
                raise ValueError('Incomplete imported fingerprint metadata')
            current['fingerprint'] = normalize_fingerprint(fields[9])
        elif fields[0] == 'uid' and len(fields) > 9 and fields[1] not in ('r', 'e', 'd', 'i'):
            identities.append(fields[9])
    primary = [key for key in keys if key['kind'] == 'sec']
    if len(primary) != 1 or primary[0]['fingerprint'] != expected:
        raise ValueError('Imported production key fingerprint mismatch')
    def usable(key):
        return (key['validity'] not in ('r', 'e', 'd', 'i') and 'D' not in key['capabilities']
                and (not key['expiry'] or int(key['expiry']) == 0 or int(key['expiry']) > time.time()))
    if not usable(primary[0]) or PRODUCTION_IDENTITY not in identities:
        raise ValueError('Imported production key validity or identity mismatch')
    if primary[0]['algorithm'] not in ('22', '27') or (primary[0]['algorithm'] == '22' and primary[0]['curve'] != 'ed25519'):
        raise ValueError('Expected Ed25519 production key')
    if not any(usable(key) and 's' in key['capabilities'] for key in keys):
        raise ValueError('Imported production key has no usable signing capability')
    return expected


def load_builder():
    spec = importlib.util.spec_from_file_location('apt_builder', ROOT / 'scripts/build-cyberrecon-apt.py')
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)
    return builder


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('package')
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    key = os.environ.get('APT_SIGNING_PRIVATE_KEY', '')
    password = os.environ.get('APT_SIGNING_PASSPHRASE', '')
    fingerprint = os.environ.get('APT_SIGNING_FINGERPRINT', '')
    if not key or not password or not fingerprint:
        parser.error('PRODUCTION SIGNING KEY REQUIRED. Protected production signing secrets and full fingerprint are required.')
    try:
        fingerprint = normalize_fingerprint(fingerprint)
        if fingerprint != PRODUCTION_FINGERPRINT:
            raise ValueError('Configured fingerprint differs from the approved production identity')
    except ValueError as error:
        parser.error(str(error))
    temporary_root = Path(os.environ.get('RUNNER_TEMP', tempfile.gettempdir())).resolve()
    if temporary_root == ROOT or ROOT in temporary_root.parents:
        parser.error('Signing temporary directory must be outside the repository.')
    builder = load_builder()
    old_umask = os.umask(0o077)
    try:
        with tempfile.TemporaryDirectory(prefix='cyberrecon-production-sign-', dir=temporary_root) as temporary:
            home = Path(temporary)
            home.chmod(0o700)
            passphrase = home / 'passphrase'
            descriptor = os.open(passphrase, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, 'w') as stream:
                stream.write(password)
            old_home = os.environ.get('GNUPGHOME')
            os.environ['GNUPGHOME'] = temporary
            for name in ('APT_SIGNING_PRIVATE_KEY', 'APT_SIGNING_PASSPHRASE'):
                os.environ.pop(name, None)
            try:
                subprocess.run(['gpg', '--batch', '--pinentry-mode', 'loopback', '--passphrase-file', str(passphrase), '--import'],
                               input=key.encode(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                               check=True, timeout=30)
                key = password = ''
                listing = subprocess.run(['gpg', '--batch', '--with-colons', '--with-fingerprint',
                                          '--with-subkey-fingerprint', '--list-secret-keys'],
                                         stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
                                         check=True, timeout=30).stdout
                fingerprint = inspect_imported_key(listing, fingerprint)
                # GPG may choose a usable subkey belonging to this exact primary;
                # the repository verifier checks its approved primary fingerprint.
                builder.build([args.package], args.output, signing_key=fingerprint, passphrase_file=passphrase)
            finally:
                try:
                    subprocess.run(['gpgconf', '--kill', 'gpg-agent'], stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL, timeout=10)
                finally:
                    if old_home is None:
                        os.environ.pop('GNUPGHOME', None)
                    else:
                        os.environ['GNUPGHOME'] = old_home
    except (ValueError, subprocess.SubprocessError, OSError):
        # Never include import output, secret input or exception payloads in logs.
        parser.error('Production signing failed: imported identity/capability, import or signing validation failed.')
    finally:
        os.umask(old_umask)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
