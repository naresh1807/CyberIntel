#!/usr/bin/env python3
"""Protected-runner signing: key material stays outside source/artifacts."""
import argparse
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


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
    temporary_root = Path(os.environ.get('RUNNER_TEMP', tempfile.gettempdir())).resolve()
    if temporary_root == ROOT or ROOT in temporary_root.parents:
        parser.error('Signing temporary directory must be outside the repository.')
    spec = importlib.util.spec_from_file_location('apt_builder', ROOT / 'scripts/build-cyberrecon-apt.py')
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)
    with tempfile.TemporaryDirectory(prefix='cyberrecon-production-sign-', dir=temporary_root) as temporary:
        home = Path(temporary)
        home.chmod(0o700)
        passphrase = home / 'passphrase'
        descriptor = os.open(passphrase, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, 'w') as stream:
            stream.write(password)
        # Remove secrets from subprocess environments; import only through stdin.
        old_home = os.environ.get('GNUPGHOME')
        os.environ['GNUPGHOME'] = temporary
        for name in ('APT_SIGNING_PRIVATE_KEY', 'APT_SIGNING_PASSPHRASE'):
            os.environ.pop(name, None)
        try:
            subprocess.run(['gpg', '--batch', '--import'], input=key.encode(), stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, check=True, timeout=30)
            key = password = ''
            builder.build([args.package], args.output, signing_key=fingerprint, passphrase_file=passphrase)
        finally:
            try:
                subprocess.run(['gpgconf', '--kill', 'gpg-agent'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
            finally:
                if old_home is None:
                    os.environ.pop('GNUPGHOME', None)
                else:
                    os.environ['GNUPGHOME'] = old_home
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
