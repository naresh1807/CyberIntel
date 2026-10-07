#!/usr/bin/env python3
"""Bounded release archive/path/permission/key checks, not a vulnerability audit."""
import argparse
import ast
import json
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import tarfile
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
PRIVATE = re.compile(rb'^-----BEGIN (?:[A-Z0-9 ]*PRIVATE KEY|PGP PRIVATE KEY BLOCK)-----', re.M)
TOKEN = re.compile(rb'(?:gh[pousr]_[A-Za-z0-9]{30,}|AKIA[A-Z0-9]{16})')


def safe_name(name):
    path = PurePosixPath(name)
    if path.is_absolute() or '..' in path.parts or '\\' in name:
        raise ValueError('Unsafe archive member path')
    return path


def check_bytes(data):
    if PRIVATE.search(data) or TOKEN.search(data):
        raise ValueError('Potential private key or credential in release input')


def check_deb(path):
    with subprocess.Popen(['dpkg-deb', '--fsys-tarfile', str(path)], stdout=subprocess.PIPE) as process:
        with tarfile.open(fileobj=process.stdout, mode='r|') as archive:
            for entry in archive:
                name = safe_name(entry.name)
                if name.parts and name.parts[0] != 'usr':
                    raise ValueError('Unexpected system install path')
                if entry.issym() or entry.islnk() or not (entry.isfile() or entry.isdir()):
                    raise ValueError('Unsupported package link/device')
                if entry.uid or entry.gid or entry.mode & 0o6022:
                    raise ValueError('Unsafe package owner or writable/set-ID mode')
                if entry.isfile():
                    if entry.size > 64 * 1024 * 1024:
                        raise ValueError('Release member exceeds bound')
                    data = archive.extractfile(entry).read()
                    check_bytes(data)
                    if entry.mode & 0o111 and str(name) not in ('usr/bin/cyberrecon', 'usr/bin/cyberrecon-dns'):
                        raise ValueError('Unexpected executable package payload')
        if process.wait(timeout=60):
            raise ValueError('Debian archive reader failed')
    metadata = subprocess.check_output(['dpkg-deb', '-f', str(path)], text=True, timeout=10)
    if 'Package: cyberrecon\n' not in metadata or not ('Architecture: all\n' in metadata or 'Architecture: amd64\n' in metadata):
        raise ValueError('Unsupported release identity/architecture')


def check_artifact(path):
    if path.suffix == '.deb':
        check_deb(path)
    elif path.suffix == '.whl':
        with zipfile.ZipFile(path) as archive:
            for entry in archive.infolist():
                safe_name(entry.filename)
                mode = entry.external_attr >> 16
                # Wheel writers can emit RECORD with group-write metadata.
                # Unlike dpkg payloads, pip installs files with its own modes.
                if stat.S_ISLNK(mode) or mode & 0o6002:
                    raise ValueError('Unsafe wheel link or world-writable/set-ID mode')
                if entry.file_size > 64 * 1024 * 1024:
                    raise ValueError('Wheel member exceeds bound')
                if not entry.is_dir():
                    check_bytes(archive.read(entry))
    elif path.name.endswith('.tar.gz'):
        with tarfile.open(path) as archive:
            for entry in archive:
                safe_name(entry.name)
                if not (entry.isfile() or entry.isdir()) or entry.size > 64 * 1024 * 1024:
                    raise ValueError('Unsafe source archive member')
                if entry.isfile():
                    check_bytes(archive.extractfile(entry).read())
    elif path.suffix in ('.asc', '.pem', '.key', '.gpg', '.p12', '.pfx'):
        check_bytes(path.read_bytes())
        if path.suffix in ('.p12', '.pfx', '.key'):
            raise ValueError('Private-key container extension is not a release artifact')
        if path.suffix == '.gpg':
            with tempfile.TemporaryDirectory(prefix='cyberrecon-key-check-') as home:
                packets = subprocess.check_output(['gpg', '--no-options', '--homedir', home, '--batch', '--list-packets', str(path)], stderr=subprocess.DEVNULL, timeout=10)
            if b'secret key packet' in packets or b'secret sub key packet' in packets:
                raise ValueError('Secret OpenPGP packets found')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--artifacts')
    args = parser.parse_args()
    files = subprocess.check_output(['git', 'ls-files', '-c', '-o', '--exclude-standard'], cwd=ROOT, text=True).splitlines()
    checked = 0
    for name in files:
        path = ROOT / name
        if not path.is_file() or path.is_symlink():
            continue
        data = path.read_bytes()
        check_bytes(data)
        if name.startswith(('cyberrecon/', 'cyberintel/', 'scripts/')) and path.suffix == '.py':
            for node in ast.walk(ast.parse(data)):
                if isinstance(node, ast.Call) and any(k.arg == 'shell' and isinstance(k.value, ast.Constant) and k.value.value is True for k in node.keywords):
                    raise ValueError('shell=True in application/release Python')
        if path.suffix in ('.gpg', '.key', '.p12', '.pfx'):
            check_artifact(path)
        checked += 1
    artifacts = 0
    if args.artifacts:
        for path in Path(args.artifacts).rglob('*'):
            if path.is_symlink():
                raise ValueError('Symlink in release artifacts')
            if path.is_file():
                check_artifact(path)
                artifacts += 1
    print(json.dumps({'source_files_checked': checked, 'artifact_files_checked': artifacts, 'status': 'PASS',
                      'limits': 'Heuristic credential/AST checks; dependency audit and reviewer assessment are separate.'}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
