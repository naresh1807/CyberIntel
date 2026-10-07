#!/usr/bin/env python3
"""Reject altered copies of a verified repository; never modifies the input."""
import argparse
import json
from pathlib import Path
import shutil
import tempfile

from verify_cyberrecon_apt import verify


def check(directory, keyring, fingerprint, production=False):
    root = Path(directory).resolve()
    keyring = Path(keyring).resolve()
    verify(root, keyring, fingerprint, production=production)
    members = ['main/binary-amd64/Packages', 'main/binary-amd64/Packages.gz',
               'Release', 'InRelease', 'Release.gpg']
    cases = [(name, False) for name in members] + [('InRelease', True), ('Release.gpg', True)]
    rejected = []
    with tempfile.TemporaryDirectory(prefix='cyberrecon-apt-tamper-') as temporary:
        for index, (member, missing) in enumerate(cases):
            copy = Path(temporary) / str(index)
            shutil.copytree(root, copy)
            path = copy / 'dists/stable' / member
            if missing:
                path.unlink()
            else:
                path.write_bytes(path.read_bytes() + b'corruption')
            try:
                verify(copy, keyring, fingerprint, production=production)
            except ValueError:
                rejected.append(('missing ' if missing else 'modified ') + member)
            else:
                raise ValueError('Verifier accepted tampering: ' + member)
    return {'status': 'PASS', 'rejected': rejected}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('repository')
    parser.add_argument('--keyring', required=True)
    parser.add_argument('--fingerprint', required=True)
    parser.add_argument('--production', action='store_true')
    args = parser.parse_args()
    print(json.dumps(check(args.repository, args.keyring, args.fingerprint, args.production)))
