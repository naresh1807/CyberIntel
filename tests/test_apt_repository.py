"""Real Debian/GPG tooling on disposable development fixtures; no host install."""
import importlib.util
from pathlib import Path
import os
import pwd
import shutil
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[1]


def module(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), ROOT / 'scripts' / (name + '.py'))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


@pytest.fixture(scope='module')
def signed_repository(tmp_path_factory):
    root = tmp_path_factory.mktemp('signed-apt')
    package = module('build-cyberrecon-deb').build(root / 'packages')
    old_stage = root / 'old-fixture'
    subprocess.run(['dpkg-deb', '-R', str(package), str(old_stage)], check=True)
    control = old_stage / 'DEBIAN/control'
    control.write_text(control.read_text().replace('Version: 0.2.0-5', 'Version: 0.2.0-4'))
    previous = root / 'packages/cyberrecon_0.2.0-4_all.deb'
    subprocess.run(['dpkg-deb', '--root-owner-group', '--build', str(old_stage), str(previous)], check=True)
    repository = module('build-cyberrecon-apt').build([previous, package], root / 'repository', development_key=True)
    fingerprint = (repository / 'SIGNING.txt').read_text().splitlines()[0].split(': ')[1]
    return repository, fingerprint


def test_signed_repository_and_hash_chain(signed_repository):
    root, fingerprint = signed_repository
    result = module('verify_cyberrecon_apt').verify(root, root / 'cyberrecon-archive-keyring.gpg', fingerprint)
    assert result['status'] == 'PASS' and result['versions'] == ['0.2.0-4', '0.2.0-5']
    assert result['architecture'] == 'amd64'
    assert not (root / 'dists/stable/main/binary-arm64').exists()


@pytest.mark.parametrize('member', ['dists/stable/InRelease', 'dists/stable/Release.gpg', 'dists/stable/Release',
                                  'dists/stable/main/binary-amd64/Packages',
                                  'dists/stable/main/binary-amd64/Packages.gz',
                                  'pool/main/c/cyberrecon/cyberrecon_0.2.0-5_all.deb'])
def test_tampered_repository_rejected(signed_repository, tmp_path, member):
    original, fingerprint = signed_repository
    repository = tmp_path / 'tampered'
    shutil.copytree(original, repository)
    path = repository / member
    path.write_bytes(path.read_bytes() + b'corruption')
    with pytest.raises(ValueError):
        module('verify_cyberrecon_apt').verify(repository, original / 'cyberrecon-archive-keyring.gpg', fingerprint)


def test_wrong_fingerprint_and_development_publication_rejected(signed_repository):
    root, fingerprint = signed_repository
    verifier = module('verify_cyberrecon_apt')
    with pytest.raises(ValueError, match='fingerprint'):
        verifier.verify(root, root / 'cyberrecon-archive-keyring.gpg', '0' * 40)
    with pytest.raises(ValueError, match='production'):
        verifier.verify(root, root / 'cyberrecon-archive-keyring.gpg', fingerprint, production=True)


def test_private_key_cannot_enter_repository(signed_repository, tmp_path):
    original, fingerprint = signed_repository
    root = tmp_path / 'private'
    shutil.copytree(original, root)
    (root / 'accidental.asc').write_bytes(b'-----BEGIN ' + b'PGP PRIVATE KEY BLOCK-----\nsynthetic')
    with pytest.raises(ValueError, match='private key'):
        module('verify_cyberrecon_apt').verify(root, original / 'cyberrecon-archive-keyring.gpg', fingerprint)


def apt_options(root, tmp_path):
    # This tests APT authentication/index resolution, not a package transaction,
    # a real old application binary, HTTPS hosting or a clean distribution VM.
    for name in ('lists/partial', 'cache/archives/partial', 'log', 'etc'):
        (tmp_path / name).mkdir(parents=True, exist_ok=True)
    status = tmp_path / 'status'
    status.write_text('')
    source = tmp_path / 'etc/source.list'
    source.write_text('deb [arch=amd64 signed-by=' + str(root / 'cyberrecon-archive-keyring.gpg') + '] ' + root.as_uri() + ' stable main\n')
    options = ['-o', 'Dir::Etc::main=-', '-o', 'Dir::Etc::parts=-',
               '-o', 'Dir::Etc::sourcelist=' + str(source), '-o', 'Dir::Etc::sourceparts=-',
               '-o', 'Dir::Etc::trusted=-', '-o', 'Dir::Etc::trustedparts=-',
               '-o', 'Dir::State::lists=' + str(tmp_path / 'lists'),
               '-o', 'Dir::State::status=' + str(status), '-o', 'Dir::Cache=' + str(tmp_path / 'cache'),
               '-o', 'Dir::Log=' + str(tmp_path / 'log'), '-o', 'APT::Architecture=amd64',
               '-o', 'APT::Sandbox::User=' + pwd.getpwuid(os.getuid()).pw_name]
    return options


def test_real_apt_update_and_candidate_policy(signed_repository, tmp_path):
    root, _ = signed_repository
    options = apt_options(root, tmp_path)
    result = subprocess.run(['apt-get', *options, 'update', '--error-on=any'], capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stdout + result.stderr
    assert not any(error in result.stdout + result.stderr for error in ('NO_PUBKEY', 'BADSIG', 'not signed'))
    policy = subprocess.check_output(['apt-cache', *options, 'policy', 'cyberrecon'], text=True, timeout=20)
    assert 'Candidate: 0.2.0-5' in policy and '0.2.0-4' in policy and 'stable/main amd64' in policy


def test_real_apt_rejects_unsigned_repository(signed_repository, tmp_path):
    original, _ = signed_repository
    root = tmp_path / 'unsigned'
    shutil.copytree(original, root)
    (root / 'dists/stable/InRelease').unlink()
    (root / 'dists/stable/Release.gpg').unlink()
    result = subprocess.run(['apt-get', *apt_options(root, tmp_path / 'client'), 'update', '--error-on=any'],
                            capture_output=True, text=True, timeout=60)
    assert result.returncode != 0
    assert 'not signed' in result.stderr + result.stdout


def test_release_workflow_keeps_signing_secrets_outside_artifact_paths():
    import re
    workflow = (ROOT / '.github/workflows/release-apt.yml').read_text()
    assert 'workflow_dispatch:' in workflow and 'pull_request' not in workflow
    sign = workflow.split('\n  sign:', 1)[1].split('\n  deploy:', 1)[0]
    assert 'name: cyberrecon-production' in sign
    assert 'if: always()' in sign and 'umask 077' in sign
    for secret in ('APT_SIGNING_PRIVATE_KEY', 'APT_SIGNING_PASSPHRASE'):
        reference = '${{ secrets.' + secret + ' }}'
        assert workflow.count(reference) == 1 and reference in sign
        assert '$' + secret not in sign
    assert 'sign_cyberrecon_release.py' in sign
    paths = re.findall(r'path: (.+)', workflow)
    assert paths and all(path.startswith('dist/release') for path in paths)


@pytest.mark.parametrize('member', ['InRelease', 'Release.gpg'])
def test_missing_signature_rejected(signed_repository, tmp_path, member):
    original, fingerprint = signed_repository
    repository = tmp_path / 'missing'
    shutil.copytree(original, repository)
    (repository / 'dists/stable' / member).unlink()
    with pytest.raises(ValueError):
        module('verify_cyberrecon_apt').verify(repository, original / 'cyberrecon-archive-keyring.gpg', fingerprint)


def test_different_signing_key_rejected_even_if_trusted(signed_repository, tmp_path):
    original, fingerprint = signed_repository
    packages = sorted((original / 'pool/main/c/cyberrecon').glob('*.deb'))
    other = module('build-cyberrecon-apt').build(packages, tmp_path / 'other', development_key=True)
    combined = tmp_path / 'both-public-keys.gpg'
    combined.write_bytes((original / 'cyberrecon-archive-keyring.gpg').read_bytes() +
                         (other / 'cyberrecon-archive-keyring.gpg').read_bytes())
    with pytest.raises(ValueError, match='fingerprint'):
        module('verify_cyberrecon_apt').verify(other, combined, fingerprint)


def test_runtime_tamper_checks_preserve_original(signed_repository):
    original, fingerprint = signed_repository
    before = {str(p.relative_to(original)): p.read_bytes() for p in original.rglob('*') if p.is_file()}
    result = module('test_cyberrecon_apt_tampering').check(original, original / 'cyberrecon-archive-keyring.gpg', fingerprint)
    assert result['status'] == 'PASS' and len(result['rejected']) == 7
    assert before == {str(p.relative_to(original)): p.read_bytes() for p in original.rglob('*') if p.is_file()}
