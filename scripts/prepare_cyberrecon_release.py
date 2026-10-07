#!/usr/bin/env python3
"""Fail-closed public release gate and SHA256 manifest generation."""
import argparse
import hashlib
import json
import importlib.metadata
import os
from pathlib import Path
import platform
import re
import subprocess
from datetime import datetime, timezone
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
REQUIRED_GATES = ('full_tests', 'kali_desktop', 'parrot_desktop', 'fresh_install',
                  'upgrade', 'reboot', 'remove', 'purge', 'reinstall', 'gui_launcher',
                  'nonroot_cli', 'scope', 'tls', 'subprocess', 'permissions',
                  'secrets', 'apt', 'signing', 'license', 'maintainer', 'workflow')


def production_gate(environment, qualification=None):
    maintainer = environment.get('CYBERRECON_MAINTAINER', '')
    url = urlsplit(environment.get('APT_PUBLIC_URL', ''))
    if not re.fullmatch(r'[^<>\r\n]+ <[^<>\s@]+@[^<>\s@]+\.[^<>\s@]+>', maintainer) or 'invalid.example' in maintainer:
        raise ValueError('MAINTAINER IDENTITY REQUIRED')
    if url.scheme != 'https' or not url.hostname or url.username or url.password or url.query or url.fragment:
        raise ValueError('Configured HTTPS APT hosting URL required')
    if environment.get('RELEASE_QUALIFIED_COMMIT') != environment.get('GITHUB_SHA') or not re.fullmatch(r'[a-f0-9]{40}', environment.get('GITHUB_SHA', '')):
        raise ValueError('Desktop/VM and default-APT qualification for this exact commit required')
    if qualification is None:
        # Reviewed environment evidence can identify the already committed SHA;
        # embedding a commit's own hash in that commit would be self-referential.
        raw = environment.get('RELEASE_QUALIFICATION_JSON')
        qualification = json.loads(raw if raw else (ROOT / 'docs/release-evidence/final-production-gate.json').read_text())
    if (qualification.get('decision') != 'APPROVED' or qualification.get('source_tree_dirty') is not False
            or qualification.get('commit') != environment['GITHUB_SHA']
            or qualification.get('version') != '0.2.0' or qualification.get('package_version') != '0.2.0-5'):
        raise ValueError('Approved exact-commit production evidence required')
    gates = qualification.get('gates', {})
    if any(not isinstance(gates.get(name), dict) or gates[name].get('status') != 'PASS'
           or not isinstance(gates[name].get('evidence'), str) or not gates[name]['evidence'].strip()
           for name in REQUIRED_GATES):
        raise ValueError('Every mandatory release gate needs PASS with reviewed evidence')


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


def build_manifest(directory):
    root = Path(directory)
    files = {}
    for path in sorted(root.iterdir()):
        if path.is_symlink():
            raise ValueError('Release directory cannot contain symlinks')
        if path.is_file() and path.name not in ('SHA256SUMS', 'build-manifest.json'):
            files[path.name] = hashlib.sha256(path.read_bytes()).hexdigest()
    packages = []
    for path in sorted(root.glob('*.deb')):
        values = subprocess.check_output(['dpkg-deb', '-f', str(path), 'Package', 'Version', 'Architecture', 'Depends'],
                                         text=True, timeout=10)
        packages.append({'filename': path.name, 'metadata': values})
    report = {'source_commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
              'source_tree_dirty': bool(subprocess.check_output(['git', 'status', '--porcelain'], cwd=ROOT)),
              'build_date_utc': datetime.now(timezone.utc).isoformat(),
              'source_date_epoch': os.environ.get('SOURCE_DATE_EPOCH'),
              'python': platform.python_version(), 'os': platform.platform(),
              'architecture': platform.machine(), 'packages': packages,
              'dependency_versions': {d.metadata['Name']: d.version for d in importlib.metadata.distributions()
                                      if d.metadata.get('Name')}, 'artifact_sha256': files}
    (root / 'build-manifest.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--production-gate', action='store_true')
    parser.add_argument('--checksums')
    parser.add_argument('--build-manifest')
    args = parser.parse_args()
    if args.production_gate:
        production_gate(os.environ)
    if args.build_manifest:
        build_manifest(args.build_manifest)
    if args.checksums:
        checksums(args.checksums)
