#!/usr/bin/env python3
"""Verify Debian staging lifecycle without installing on or modifying the host.

This is not a clean distribution apt install test: dependencies come from the
current interpreter. dpkg extraction/upgrade/removal is simulated in temp roots.
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('package')
    args = parser.parse_args()
    package = Path(args.package).resolve()
    with tempfile.TemporaryDirectory(prefix='cyberrecon-package-check-') as temporary:
        root = Path(temporary)
        stage, home = root / 'stage', root / 'user-workspace'
        subprocess.run(['dpkg-deb', '-x', str(package), str(stage)], check=True, timeout=30)
        control = root / 'control'
        subprocess.run(['dpkg-deb', '-e', str(package), str(control)], check=True, timeout=30)
        metadata = subprocess.check_output(['dpkg-deb', '-f', str(package)], text=True, timeout=10)
        assert 'Depends: python3 (>= 3.12)' in metadata
        assert not any((control / name).exists() for name in ('preinst','postinst','postrm'))
        prerm = control / 'prerm'
        assert prerm.stat().st_mode & 0o111
        assert prerm.read_text() == '#!/bin/sh\nset -e\ncase "${1:-}" in\n  remove|upgrade|deconfigure) py3clean -p cyberrecon ;;\nesac\nexit 0\n'
        application = stage / 'usr/share/cyberrecon'
        launcher = stage / 'usr/bin/cyberrecon'
        worker = stage / 'usr/bin/cyberrecon-dns'
        if worker.exists():
            version = subprocess.check_output([str(worker), '--version'], text=True, timeout=5)
            assert version.strip() == 'cyberrecon-dns 0.2.0'
        assert (stage / 'usr/share/doc/cyberrecon/docs/AUDIT.md').is_file()
        assert launcher.stat().st_mode & 0o111
        assert "'/usr/share/cyberrecon'" in launcher.read_text()
        desktop = stage / 'usr/share/applications/cyberrecon.desktop'
        assert 'Exec=/usr/bin/cyberrecon' in desktop.read_text()
        assert 'Icon=cyberrecon' in desktop.read_text()
        assert (stage / 'usr/share/icons/hicolor/scalable/apps/cyberrecon.svg').is_file()
        assert (application / 'cyberrecon/assets/cyberrecon.svg').is_file()
        assert (stage / 'usr/share/doc/cyberrecon/copyright').read_text().startswith('MIT License')
        environment = {**os.environ, 'PYTHONPATH': str(application), 'CYBERRECON_HOME': str(home), 'QT_QPA_PLATFORM': 'offscreen'}
        for flag in ('--version', '--help'):
            subprocess.run([sys.executable, '-m', 'cyberrecon', flag], cwd=root, env=environment, check=True, timeout=15, stdout=subprocess.DEVNULL)
        # Native/import startup must not depend on omitted CyberIntel GUI modules.
        created = subprocess.check_output([sys.executable, '-m', 'cyberrecon', 'project', 'Packaging fixture',
                    '--include', '127.0.0.1', '--authority', 'Own local package fixture'], cwd=root, env=environment, text=True, timeout=15)
        assert json.loads(created)
        marker = home / 'user-config.json'; marker.write_text('{"fixture":true}')
        db_before = (home / 'cyberrecon.db').read_bytes()
        # Overlay reinstallation/upgrade payload in isolated filesystem only.
        subprocess.run(['dpkg-deb', '-x', str(package), str(stage)], check=True, timeout=30)
        assert marker.read_text() == '{"fixture":true}' and (home / 'cyberrecon.db').read_bytes() == db_before
        # Package removal does not touch user-owned state; package has no hooks.
        shutil.rmtree(stage)
        assert marker.exists() and (home / 'cyberrecon.db').exists()
        print(json.dumps({'package_staging': 'PASS', 'entry_points': 'PASS', 'database_creation': 'PASS',
                          'overlay_preserves_state': 'PASS', 'staged_removal_preserves_state': 'PASS',
                          'clean_kali_parrot_apt_lifecycle': 'NOT_TESTED_BY_THIS_CHECK'}, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
