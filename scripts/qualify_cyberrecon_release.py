#!/usr/bin/env python3
"""Real dpkg/APT lifecycle checks, exclusively in an explicitly disposable OS.

Requires /run/cyberrecon-disposable-root containing RELEASE_TEST_ONLY. Never
create this marker on a production host. Saves partial evidence on failure.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import sqlite3
import subprocess
import sys


def workspace_fingerprint(home):
    """Hash logical SQLite state and every report, independent of WAL layout."""
    home = Path(home)
    database = home / 'cyberrecon.db'
    if home.is_symlink() or database.is_symlink():
        raise ValueError('Qualification workspace cannot be a symlink')
    with sqlite3.connect(database.as_uri() + '?mode=ro', uri=True) as connection:
        if connection.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
            raise ValueError('Qualification database integrity failure')
        schema = connection.execute('PRAGMA user_version').fetchone()[0]
        dump = '\n'.join(connection.iterdump()).encode()
    reports = {}
    for path in sorted((home / 'reports').rglob('*')):
        if path.is_symlink():
            raise ValueError('Qualification reports cannot be symlinks')
        if path.is_file():
            reports[path.relative_to(home).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    return {'schema': schema, 'database_state_sha256': hashlib.sha256(dump).hexdigest(),
            'reports': reports}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('previous')
    parser.add_argument('current')
    parser.add_argument('--output', default='/tmp/cyberrecon-qualification')
    parser.add_argument('--no-install-recommends', action='store_true', help='Test the minimal runtime dependency installation path')
    args = parser.parse_args()
    marker = Path('/run/cyberrecon-disposable-root')
    if os.geteuid() != 0 or not marker.is_file() or marker.read_text().strip() != 'RELEASE_TEST_ONLY':
        parser.error('Refusing system package changes outside a marked disposable root.')
    previous, current = Path(args.previous).resolve(), Path(args.current).resolve()
    out = Path(args.output).resolve()
    out.mkdir(parents=True, exist_ok=True)
    home = out / 'workspace'
    env = {**os.environ, 'CYBERRECON_HOME': str(home), 'QT_QPA_PLATFORM': 'offscreen', 'DEBIAN_FRONTEND': 'noninteractive'}
    report = {'status': 'RUNNING', 'os_release': Path('/etc/os-release').read_text(),
              'kernel': platform.platform(), 'python': sys.version, 'uid': os.getuid(),
              'gui_mode': 'offscreen; real desktop NOT_TESTED', 'checks': {}}
    report['install_recommends'] = not args.no_install_recommends
    repair = ['apt-get', '-o', 'APT::Sandbox::User=root', 'install', '-f', '-y']
    if args.no_install_recommends:
        repair.append('--no-install-recommends')
    report_path = out / 'qualification.json'

    def save():
        report_path.write_text(json.dumps(report, indent=2))

    def run(name, argv, allowed=(0,), timeout=180):
        log = out / (name + '.log')
        report['checks'][name] = {'status': 'RUNNING'}
        save()
        try:
            with log.open('w') as stream:
                result = subprocess.run(argv, cwd='/tmp', env=env, stdout=stream,
                                        stderr=subprocess.STDOUT, timeout=timeout)
        except subprocess.TimeoutExpired:
            report['checks'][name] = {'status': 'TIMEOUT'}
            save()
            raise
        report['checks'][name] = {'returncode': result.returncode, 'status': 'PASS' if result.returncode in allowed else 'FAIL'}
        save()
        if result.returncode not in allowed:
            raise RuntimeError(name + ' failed; see ' + str(out / (name + '.log')))
        return log.read_text(errors='replace')

    preserved_reports = {}
    preserved_lab = None
    scripts = Path(__file__).resolve().parent
    lab_home = out / 'lab-before-upgrade'

    def fixture():
        with sqlite3.connect(home / 'cyberrecon.db') as db:
            assert db.execute('PRAGMA integrity_check').fetchone()[0] == 'ok'
            assert db.execute('PRAGMA user_version').fetchone()[0] == 3
            assert db.execute('SELECT name,authority FROM projects').fetchall() == [('Lifecycle fixture', 'Own isolated loopback lab')]
            assert db.execute('SELECT status FROM scans').fetchall() == [('complete',)]
            assert db.execute('SELECT kind,key FROM observations').fetchall() == [('assets', '127.0.0.1')]
            assert db.execute('SELECT count(*) FROM scope_history').fetchone()[0] == 1
        assert (home.stat().st_mode & 0o777) == 0o700
        assert ((home / 'cyberrecon.db').stat().st_mode & 0o777) == 0o600
        assert (home / 'preservation-marker.txt').read_text() == 'Keep user data\n'
        for name, digest in preserved_reports.items():
            assert hashlib.sha256((home / 'reports/fixture' / name).read_bytes()).hexdigest() == digest
        if preserved_lab is not None:
            assert workspace_fingerprint(lab_home) == preserved_lab, 'Pre-upgrade scan/report state changed'
            assert lab_home.stat().st_mode & 0o777 == 0o700
            assert (lab_home / 'cyberrecon.db').stat().st_mode & 0o777 == 0o600

    try:
        assert sys.version_info >= (3, 12), 'Python below supported minimum'
        for name, package in [('previous', previous), ('current', current)]:
            report[name] = {'sha256': hashlib.sha256(package.read_bytes()).hexdigest(),
                            'metadata': run(name + '-metadata', ['dpkg-deb', '-f', str(package)])}
        old_version = run('previous-version', ['dpkg-deb', '-f', str(previous), 'Version']).strip()
        new_version = run('current-version', ['dpkg-deb', '-f', str(current), 'Version']).strip()
        run('version-order', ['dpkg', '--compare-versions', new_version, 'gt', old_version])
        # dpkg may leave an unpacked package until apt resolves its dependencies.
        run('install-dpkg', ['dpkg', '-i', str(previous)], allowed=(0, 1))
        run('install-dependencies', repair, timeout=900)
        assert run('installed-previous', ['dpkg-query', '-W', '-f=${Status} ${Version}', 'cyberrecon']).strip() == 'install ok installed ' + old_version
        run('create-fixture', ['cyberrecon', 'project', 'Lifecycle fixture', '--include', '127.0.0.1', '--authority', 'Own isolated loopback lab'])
        run('create-history-fixture', [sys.executable, '-c', "import sys; sys.path.insert(0,'/usr/share/cyberrecon'); from cyberrecon.storage import Repository; r=Repository(); p=r.projects()[0]['id']; s=r.start_scan(p,'127.0.0.1',{}); r.save(s,'assets','127.0.0.1',{'host':'127.0.0.1'},'Synthetic offline lifecycle fixture'); r.finish(s,[]); r.export_json(s,r.home/'reports/fixture')"])
        (home / 'preservation-marker.txt').write_text('Keep user data\n')
        preserved_reports.update({p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in (home / 'reports/fixture').iterdir()})
        assert preserved_reports
        fixture()
        previous_lab = json.loads(run('previous-installed-tls-nmap-reports',
            [sys.executable, str(scripts / 'verify_cyberrecon_lab.py'), '--package', '--tls',
             '--require-nmap', '--home', str(lab_home)], timeout=240))
        assert previous_lab['status'] == 'complete' and previous_lab['real_nmap'] and previous_lab['tls_verified']
        preserved_lab = workspace_fingerprint(lab_home)
        assert {'scan.json', 'observations.csv', 'report.html', 'report.pdf', 'graph.html'} <= {
            Path(name).name for name in preserved_lab['reports']}
        report['pre_upgrade_lab'] = previous_lab
        report['preserved_pre_upgrade_state'] = preserved_lab
        fixture()
        run('upgrade', ['apt-get', '-o', 'APT::Sandbox::User=root', 'install', '-y', '--no-install-recommends', str(current)], timeout=900)
        assert run('installed-current', ['dpkg-query', '-W', '-f=${Status} ${Version}', 'cyberrecon']).strip() == 'install ok installed ' + new_version
        assert run('cli-version', ['cyberrecon', '--version']).strip() == new_version.split('-')[0]
        run('cli-help', ['cyberrecon', '--help'])
        doctor = json.loads(run('doctor', ['cyberrecon', '--doctor']))
        assert doctor['python_status'] == 'READY'
        assert all(value['status'] == 'READY' for value in doctor['dependencies'].values()), doctor['dependencies']
        run('package-owner', ['dpkg-query', '-S', '/usr/bin/cyberrecon', '/usr/share/cyberrecon/cyberrecon/cli.py', '/usr/share/applications/cyberrecon.desktop', '/usr/share/icons/hicolor/scalable/apps/cyberrecon.svg'])
        assert Path('/usr/bin/cyberrecon').stat().st_mode & 0o777 == 0o755
        assert not Path('/usr/bin/cyberrecon').stat().st_mode & 0o6000
        fixture()
        run('gui-startup', [sys.executable, str(scripts / 'verify_cyberrecon_startup.py'), '--package'])
        lab = json.loads(run('installed-tls-nmap-reports', [sys.executable, str(scripts / 'verify_cyberrecon_lab.py'), '--package', '--tls', '--require-nmap', '--home', str(out / 'lab')], timeout=240))
        assert lab['status'] == 'complete' and lab['real_nmap'] and lab['tls_verified'], lab
        reports = Path(lab['reports'])
        for filename in ('scan.json', 'observations.csv', 'report.html', 'report.pdf', 'graph.html'):
            assert (reports / filename).stat().st_size > 0
        report['lab'] = lab
        assert not run('dpkg-audit', ['dpkg', '--audit']).strip()
        run('remove', ['apt-get', '-o', 'APT::Sandbox::User=root', 'remove', '-y', 'cyberrecon'])
        assert not Path('/usr/bin/cyberrecon').exists()
        assert not Path('/usr/share/applications/cyberrecon.desktop').exists()
        assert not Path('/usr/share/icons/hicolor/scalable/apps/cyberrecon.svg').exists()
        assert shutil.which('cyberrecon') is None
        fixture()
        # With no conffiles, dpkg forgets this package on
        # remove. Reinstall it before testing purge as a separate lifecycle.
        run('reinstall-before-purge', ['dpkg', '-i', str(current)])
        run('purge', ['apt-get', '-o', 'APT::Sandbox::User=root', 'purge', '-y', 'cyberrecon'])
        fixture()
        assert not Path('/usr/share/cyberrecon').exists()
        report['checks']['workspace-preservation'] = {'status': 'PASS'}
        # Install the final revision with no CyberRecon package present, too.
        run('fresh-install-dpkg', ['dpkg', '-i', str(current)], allowed=(0, 1))
        run('fresh-install-dependencies', repair, timeout=900)
        assert run('fresh-installed-version', ['cyberrecon', '--version']).strip() == new_version.split('-')[0]
        fresh = out / 'fresh-workspace'
        env['CYBERRECON_HOME'] = str(fresh)
        run('fresh-create-workspace', ['cyberrecon', 'project', 'Fresh fixture', '--include', '127.0.0.1', '--authority', 'Own isolated loopback lab'])
        assert (fresh.stat().st_mode & 0o777) == 0o700
        assert ((fresh / 'cyberrecon.db').stat().st_mode & 0o777) == 0o600
        run('fresh-remove-purge', ['apt-get', '-o', 'APT::Sandbox::User=root', 'purge', '-y', 'cyberrecon'])
        assert not Path('/usr/bin/cyberrecon').exists() and not Path('/usr/share/cyberrecon').exists()
        assert (fresh / 'cyberrecon.db').exists()
        fixture()
        report['status'] = 'PASS'
    except Exception as exc:
        report['status'] = 'FAIL'
        report['failure'] = str(exc)
        raise
    finally:
        save()
    print(json.dumps(report, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
