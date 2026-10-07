"""Production identity checks use mock metadata, never the owner's secret key."""
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]


def signer():
    spec = importlib.util.spec_from_file_location('production_signer_test', ROOT / 'scripts/sign_cyberrecon_release.py')
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def listing(module, fingerprint=None, uid=None, caps='scSC', expiry='', algorithm='22'):
    values = [''] * 20
    values[0], values[1], values[2], values[3] = 'sec', 'u', '255', algorithm
    values[6], values[11], values[16] = expiry, caps, 'ed25519'
    uid_fields = [''] * 12
    uid_fields[0], uid_fields[1], uid_fields[9] = 'uid', 'u', uid or module.PRODUCTION_IDENTITY
    return ':'.join(values) + '\nfpr:::::::::' + (fingerprint or module.PRODUCTION_FINGERPRINT) + ':\n' + ':'.join(uid_fields) + '\n'


@pytest.mark.parametrize('spaced', [False, True])
def test_matching_imported_production_fingerprint(spaced):
    module = signer()
    fingerprint = module.PRODUCTION_FINGERPRINT
    if spaced:
        fingerprint = ' '.join(fingerprint[i:i+4] for i in range(0, len(fingerprint), 4)).lower()
    assert module.inspect_imported_key(listing(module), fingerprint) == module.PRODUCTION_FINGERPRINT


@pytest.mark.parametrize('change', ['fingerprint', 'identity', 'capability', 'expiry', 'algorithm', 'extra_key'])
def test_imported_production_identity_rejected(change):
    module = signer()
    options = {'fingerprint': '0'*40} if change == 'fingerprint' else {}
    if change == 'identity': options['uid'] = 'Synthetic different identity'
    if change == 'capability': options['caps'] = 'cC'
    if change == 'expiry': options['expiry'] = '1'
    if change == 'algorithm': options['algorithm'] = '1'
    data = listing(module, **options)
    if change == 'extra_key': data += listing(module)
    with pytest.raises(ValueError):
        module.inspect_imported_key(data, module.PRODUCTION_FINGERPRINT)


@pytest.mark.parametrize('missing', ['APT_SIGNING_PRIVATE_KEY', 'APT_SIGNING_PASSPHRASE', 'APT_SIGNING_FINGERPRINT'])
def test_missing_production_secret_fails_without_leak(missing):
    module = signer()
    environment = {key: value for key, value in os.environ.items() if not key.startswith('APT_SIGNING_')}
    environment.update(APT_SIGNING_PRIVATE_KEY='opaque-unit-import-placeholder',
                       APT_SIGNING_PASSPHRASE='opaque-unit-password-placeholder',
                       APT_SIGNING_FINGERPRINT=module.PRODUCTION_FINGERPRINT)
    environment.pop(missing)
    result = subprocess.run([sys.executable, str(ROOT / 'scripts/sign_cyberrecon_release.py'), 'absent.deb',
                             '--output', '/tmp/unused-production-unit-output'], env=environment,
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 2
    assert 'opaque-unit-' not in result.stdout + result.stderr


@pytest.mark.parametrize('failure', [None, 'import', 'fingerprint', 'sign'])
def test_secret_handling_cleanup_and_signing_failure(tmp_path, monkeypatch, capsys, failure):
    module = signer()
    key, password = 'opaque-unit-import-placeholder', 'opaque-unit-password-placeholder'
    monkeypatch.setenv('RUNNER_TEMP', str(tmp_path))
    monkeypatch.setenv('GNUPGHOME', '/tmp/original-gpg-home-never-accessed')
    monkeypatch.setenv('APT_SIGNING_PRIVATE_KEY', key)
    monkeypatch.setenv('APT_SIGNING_PASSPHRASE', password)
    monkeypatch.setenv('APT_SIGNING_FINGERPRINT', module.PRODUCTION_FINGERPRINT)
    monkeypatch.setattr(sys, 'argv', ['signer', 'fixture.deb', '--output', str(tmp_path / 'public')])
    cleaned = []
    def run(argv, **kwargs):
        assert key not in argv and password not in argv
        assert 'APT_SIGNING_PRIVATE_KEY' not in os.environ and 'APT_SIGNING_PASSPHRASE' not in os.environ
        home = Path(os.environ['GNUPGHOME'])
        assert home.parent == tmp_path and home.stat().st_mode & 0o777 == 0o700
        if argv[0] == 'gpgconf':
            cleaned.append(True)
            return subprocess.CompletedProcess(argv, 0)
        assert (home / 'passphrase').stat().st_mode & 0o777 == 0o600
        if '--import' in argv:
            assert kwargs['input'] == key.encode() and kwargs['stdout'] == subprocess.DEVNULL and kwargs['stderr'] == subprocess.DEVNULL
            if failure == 'import': raise subprocess.CalledProcessError(1, argv)
            return subprocess.CompletedProcess(argv, 0)
        metadata = listing(module, fingerprint='0'*40) if failure == 'fingerprint' else listing(module)
        return subprocess.CompletedProcess(argv, 0, stdout=metadata)
    def build(packages, output, **kwargs):
        assert kwargs['signing_key'] == module.PRODUCTION_FINGERPRINT
        assert kwargs['passphrase_file'].read_text() == password
        if failure == 'sign': raise subprocess.CalledProcessError(1, ['gpg'])
    monkeypatch.setattr(module.subprocess, 'run', run)
    monkeypatch.setattr(module, 'load_builder', lambda: SimpleNamespace(build=build))
    if failure:
        with pytest.raises(SystemExit) as result: module.main()
        assert result.value.code == 2
    else:
        assert module.main() == 0
    assert cleaned and not list(tmp_path.glob('cyberrecon-production-sign-*'))
    assert os.environ['GNUPGHOME'] == '/tmp/original-gpg-home-never-accessed'
    captured = capsys.readouterr()
    assert key not in captured.out + captured.err and password not in captured.out + captured.err


def test_production_trust_has_no_insecure_commands():
    workflow = (ROOT / '.github/workflows/release-apt.yml').read_text()
    assert 'name: cyberrecon-production' in workflow and 'if: always()' in workflow
    for unsafe in ('trusted=yes', 'allow-insecure=yes', '--allow-unauthenticated', 'apt-key', 'set -x'):
        assert unsafe not in workflow
