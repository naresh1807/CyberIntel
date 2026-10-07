import importlib.util
from pathlib import Path
import subprocess
import sys

import pytest

from cyberrecon.doctor import doctor

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize('networkx,plotly,expected', [
    ('3.2.1', '5.20.0', 'READY'),
    ('3.2.0', '5.20.0', 'UNSUPPORTED'),
    ('3.2.1', '5.19.0', 'UNSUPPORTED'),
])
def test_doctor_distribution_dependency_boundaries(monkeypatch, tmp_path, networkx, plotly, expected):
    monkeypatch.setattr('cyberrecon.doctor.tool_status', lambda *a: {'status': 'OPTIONAL'})
    monkeypatch.setattr('cyberrecon.doctor.importlib.util.find_spec', lambda name: object())
    versions = {'networkx': networkx, 'plotly': plotly, 'numpy': '2.2.4', 'httpx': '0.28.1',
                'dnspython': '2.7.0', 'PySide6': '6.8.2', 'reportlab': '4.3.1'}
    monkeypatch.setattr('cyberrecon.doctor.importlib.metadata.version', versions.__getitem__)
    monkeypatch.setattr('cyberrecon.doctor.importlib.import_module', lambda name: None)
    result = doctor(tmp_path)['dependencies']
    assert result['numpy']['status'] == 'READY'
    assert ('UNSUPPORTED' in (result['networkx']['status'], result['plotly']['status'])) == (expected == 'UNSUPPORTED')


def test_debian_declares_graph_dependencies(tmp_path):
    spec = importlib.util.spec_from_file_location('release_builder', ROOT / 'scripts/build-cyberrecon-deb.py')
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)
    package = builder.build(tmp_path)
    dependencies = subprocess.check_output(['dpkg-deb', '-f', str(package), 'Depends'], text=True)
    # Without this direct dependency, --no-install-recommends breaks graph exports.
    assert 'python3-numpy (>= 1:2.0)' in dependencies
    assert 'python3-networkx (>= 3.2.1)' in dependencies
    assert 'python3-plotly (>= 5.20)' in dependencies
    control = tmp_path / 'control'
    subprocess.run(['dpkg-deb', '-e', str(package), str(control)], check=True)
    hook = (control / 'prerm').read_text()
    assert 'py3clean -p cyberrecon' in hook
    assert 'rm ' not in hook and 'HOME' not in hook


def test_lifecycle_refuses_unmarked_host(tmp_path):
    if Path('/run/cyberrecon-disposable-root').exists():
        pytest.skip('Disposable lifecycle environment is deliberately marked')
    result = subprocess.run([sys.executable, str(ROOT / 'scripts/qualify_cyberrecon_release.py'),
                             'absent.deb', 'absent.deb', '--output', str(tmp_path / 'evidence')],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 2
    assert 'Refusing system package changes' in result.stderr
    assert not (tmp_path / 'evidence').exists()
