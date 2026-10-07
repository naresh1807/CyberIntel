#!/usr/bin/env python3
"""Fail-closed public release gate and SHA256 manifest generation."""
import argparse
import hashlib
import os
from pathlib import Path
import re
from urllib.parse import urlsplit


def production_gate(environment):
    maintainer = environment.get('CYBERRECON_MAINTAINER', '')
    url = urlsplit(environment.get('APT_PUBLIC_URL', ''))
    if not re.fullmatch(r'[^<>\r\n]+ <[^<>\s@]+@[^<>\s@]+\.[^<>\s@]+>', maintainer) or 'invalid.example' in maintainer:
        raise ValueError('MAINTAINER IDENTITY REQUIRED')
    if url.scheme != 'https' or not url.hostname or url.username or url.password or url.query or url.fragment:
        raise ValueError('Configured HTTPS APT hosting URL required')
    if environment.get('RELEASE_QUALIFIED_COMMIT') != environment.get('GITHUB_SHA') or not re.fullmatch(r'[a-f0-9]{40}', environment.get('GITHUB_SHA', '')):
        raise ValueError('Desktop/VM and default-APT qualification for this exact commit required')


def checksums(directory):
    root = Path(directory)
    lines = []
    for path in sorted(root.rglob('*')):
        if path.is_symlink():
            raise ValueError('Release directory cannot contain symlinks')
        if path.is_file() and path.name != 'SHA256SUMS':
            name = path.relative_to(root).as_posix()
            if '\n' in name or '\r' in name:
                raise ValueError('Unsafe release filename')
            lines.append(hashlib.sha256(path.read_bytes()).hexdigest() + '  ' + name)
    (root / 'SHA256SUMS').write_text('\n'.join(lines) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--production-gate', action='store_true')
    parser.add_argument('--checksums')
    args = parser.parse_args()
    if args.production_gate:
        production_gate(os.environ)
    if args.checksums:
        checksums(args.checksums)
