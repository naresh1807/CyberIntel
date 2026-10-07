import importlib.util
import io
from pathlib import Path
import subprocess
import tarfile
import zipfile

import pytest

ROOT = Path(__file__).resolve().parents[1]


def module(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), ROOT / 'scripts' / (name + '.py'))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


@pytest.mark.parametrize('name', ['../escape', '/absolute', 'usr/../../etc/passwd', 'usr\\bin\\evil'])
def test_archive_traversal_rejected(name):
    with pytest.raises(ValueError):
        module('check_release_security').safe_name(name)


def test_private_key_and_token_rejected():
    checker = module('check_release_security')
    with pytest.raises(ValueError):
        checker.check_bytes(b'-----BEGIN ' + b'PRIVATE KEY-----\nfixture')
    with pytest.raises(ValueError):
        checker.check_bytes(b'ghp_' + b'A' * 40)


def test_malicious_source_archive_rejected(tmp_path):
    archive = tmp_path / 'malicious.tar.gz'
    with tarfile.open(archive, 'w:gz') as output:
        member = tarfile.TarInfo('../outside')
        member.size = 1
        output.addfile(member, io.BytesIO(b'x'))
    with pytest.raises(ValueError):
        module('check_release_security').check_artifact(archive)


def test_wheel_symlink_rejected(tmp_path):
    archive = tmp_path / 'malicious.whl'
    with zipfile.ZipFile(archive, 'w') as output:
        member = zipfile.ZipInfo('package/link')
        member.create_system = 3
        member.external_attr = 0o120777 << 16
        output.writestr(member, '/etc/passwd')
    with pytest.raises(ValueError, match='wheel link'):
        module('check_release_security').check_artifact(archive)


def test_production_signing_requires_secrets(tmp_path):
    import os
    import sys
    environment = {key: value for key, value in os.environ.items() if not key.startswith('APT_SIGNING_')}
    result = subprocess.run([sys.executable, str(ROOT / 'scripts/sign_cyberrecon_release.py'),
                             'absent.deb', '--output', str(tmp_path / 'repo')],
                            env=environment, capture_output=True, text=True)
    assert result.returncode == 2
    assert 'Protected production signing secrets' in result.stderr
    assert not (tmp_path / 'repo').exists()


def test_production_identity_gate_and_checksums(tmp_path):
    prepare = module('prepare_cyberrecon_release')
    with pytest.raises(ValueError, match='MAINTAINER'):
        prepare.production_gate({})
    environment = {'CYBERRECON_MAINTAINER': 'Test fixture <fixture@example.test>',
                   'APT_PUBLIC_URL': 'https://fixture.example.test/apt',
                   'GITHUB_SHA': 'a' * 40, 'RELEASE_QUALIFIED_COMMIT': 'b' * 40}
    with pytest.raises(ValueError, match='exact commit'):
        prepare.production_gate(environment)
    environment['RELEASE_QUALIFIED_COMMIT'] = 'a' * 40
    prepare.production_gate(environment)
    (tmp_path / 'package').write_bytes(b'fixture')
    prepare.checksums(tmp_path)
    subprocess.run(['sha256sum', '-c', 'SHA256SUMS'], cwd=tmp_path, check=True)


def test_deb_permissions_launcher_license_and_production_block(tmp_path):
    builder = module('build-cyberrecon-deb')
    with pytest.raises(ValueError, match='MAINTAINER'):
        builder.build(tmp_path / 'blocked', production=True)
    package = builder.build(tmp_path / 'valid')
    module('check_release_security').check_deb(package)
    stage = tmp_path / 'stage'
    subprocess.run(['dpkg-deb', '-x', str(package), str(stage)], check=True)
    launcher = stage / 'usr/share/applications/cyberrecon.desktop'
    subprocess.run(['desktop-file-validate', str(launcher)], check=True)
    assert 'Icon=cyberrecon' in launcher.read_text()
    assert (stage / 'usr/share/icons/hicolor/scalable/apps/cyberrecon.svg').is_file()
    assert (stage / 'usr/share/doc/cyberrecon/copyright').read_text().startswith('MIT License')


def test_apt_does_not_advertise_arm(tmp_path, monkeypatch):
    builder = module('build-cyberrecon-apt')
    monkeypatch.setattr(builder.subprocess, 'check_output', lambda *a, **k: 'arm64\n')
    with pytest.raises(ValueError, match='architecture'):
        builder.build([tmp_path / 'fake.deb'], tmp_path / 'apt', development_key=True)


def test_doctor_reports_requirement_and_remediation(monkeypatch, tmp_path):
    from cyberrecon.doctor import doctor
    monkeypatch.setattr('cyberrecon.doctor.tool_status', lambda *a: {'status': 'OPTIONAL'})
    report = doctor(tmp_path)
    for dependency in report['dependencies'].values():
        assert dependency['requirement'] == 'Required'
        assert dependency['compatibility'] and dependency['recommended_action']


def test_package_overlay_preserves_history_reports_and_permissions(tmp_path):
    from cyberrecon.storage import Repository
    repo = Repository(tmp_path / 'home')
    project = repo.create_project('Fixture', ['127.0.0.1'], authority='Own fixture')
    scan = repo.start_scan(project, '127.0.0.1', {})
    repo.save(scan, 'assets', '127.0.0.1', {'host': '127.0.0.1'}, 'Fixture')
    repo.finish(scan, [])
    exported = Path(repo.export_json(scan, repo.home / 'reports/fixture'))
    before = {p.name: p.read_bytes() for p in exported.iterdir()}
    builder = module('build-cyberrecon-deb')
    package = builder.build(tmp_path / 'deb')
    stage = tmp_path / 'stage'
    subprocess.run(['dpkg-deb', '-x', str(package), str(stage)], check=True)
    subprocess.run(['dpkg-deb', '-x', str(package), str(stage)], check=True)
    reopened = Repository(repo.home)
    assert reopened.project(project)['authority'] == 'Own fixture'
    assert reopened.snapshot(scan)['assets'][0]['host'] == '127.0.0.1'
    assert {p.name: p.read_bytes() for p in exported.iterdir()} == before
    assert reopened.path.stat().st_mode & 0o777 == 0o600
