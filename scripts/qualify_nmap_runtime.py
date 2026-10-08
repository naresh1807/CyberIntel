#!/usr/bin/env python3
"""Diagnose Nmap execution and remove incompatible privileges only in CI's disposable root."""
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess


def missing_capabilities(data, bounding):
    """Linux effective file capabilities fail exec when permitted bits exceed CapBnd."""
    if len(data) not in (20, 24):
        return 0
    magic, permitted_low, _, permitted_high, _ = struct.unpack('<5I', data[:20])
    if magic & 0xff000000 not in (0x02000000, 0x03000000) or not magic & 1:
        return 0
    return (permitted_low | permitted_high << 32) & ~bounding


def run(argv):
    result = subprocess.run(argv, capture_output=True, text=True, timeout=30)
    print(json.dumps({'command': argv, 'returncode': result.returncode,
                      'stdout': result.stdout[:8192], 'stderr': result.stderr[:8192]}), flush=True)
    return result


def main():
    marker = Path('/run/cyberrecon-disposable-root')
    if os.geteuid() != 0 or not marker.is_file() or marker.read_text().strip() != 'RELEASE_TEST_ONLY':
        raise RuntimeError('Nmap runtime qualification requires a marked disposable root')
    status = Path('/proc/self/status').read_text()
    print('UID:', os.geteuid(), flush=True)
    print('\n'.join(line for line in status.splitlines()
                    if line.startswith(('Cap', 'NoNewPrivs:', 'Seccomp'))), flush=True)
    for name in ('/proc/self/attr/current', '/proc/self/mountinfo'):
        try:
            evidence = Path(name).read_text()
            if name.endswith('mountinfo'):
                evidence = '\n'.join(line for line in evidence.splitlines()
                                     if '/usr/lib/nmap/nmap'.startswith(line.split()[4].rstrip('/') + '/'))
            print(name + ':\n' + evidence, flush=True)
        except OSError as exc:
            print(name + ': ' + str(exc), flush=True)
    run(['dpkg-query', '-W', 'nmap'])
    integrity = run(['dpkg', '--verify', 'nmap'])
    if integrity.returncode or integrity.stdout.strip():
        raise RuntimeError('Installed Nmap package integrity check failed')
    binary = Path('/usr/lib/nmap/nmap')
    capabilities = b''
    if binary.is_file():
        print('Nmap ELF permissions:', oct(binary.stat().st_mode & 0o7777), flush=True)
        run(['dpkg-query', '-S', str(binary)])
        run(['ldd', str(binary)])
        try:
            capabilities = os.getxattr(binary, 'security.capability')
        except OSError as exc:
            print('Nmap file capabilities unavailable:', str(exc), flush=True)
        print('Nmap security.capability:', capabilities.hex(), flush=True)
    initial = run(['/usr/bin/nmap', '--version'])
    bounding = int(next(line.split()[1] for line in status.splitlines() if line.startswith('CapBnd:')), 16)
    kali = 'ID=kali' in Path('/etc/os-release').read_text().splitlines()
    if initial.returncode == 126 and kali and missing_capabilities(capabilities, bounding):
        # Kali's postinst assigns effective NET_ADMIN/NET_RAW/BIND_SERVICE.
        # Docker excludes NET_ADMIN; exec fails before --unprivileged is read.
        # Reduce this binary's privileges, never broaden container capabilities.
        before = hashlib.sha256(binary.read_bytes()).hexdigest()
        if run(['setcap', '-r', str(binary)]).returncode:
            raise RuntimeError('Could not remove incompatible Nmap file capabilities')
        if hashlib.sha256(binary.read_bytes()).hexdigest() != before:
            raise RuntimeError('Nmap executable content changed')
        print('Removed incompatible Nmap file capabilities in disposable Kali container', flush=True)
    elif initial.returncode:
        raise RuntimeError('Nmap execution failed without the diagnosed Kali capability conflict')
    if run(['/usr/bin/nmap', '--version']).returncode:
        raise RuntimeError('Nmap execution remains unavailable')


if __name__ == '__main__':
    main()
