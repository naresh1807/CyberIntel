import importlib.util
import json
import os
from pathlib import Path
import sys

spec = importlib.util.spec_from_file_location('qualification', Path(__file__).resolve().parents[1] / 'scripts/qualify_cyberrecon_release.py')
qualification = importlib.util.module_from_spec(spec)
spec.loader.exec_module(qualification)


def test_json_stdout_and_diagnostic_stderr_are_preserved_separately(tmp_path):
    log = tmp_path / 'process.log'
    child = 'import sys; print("diagnostic: real child", file=sys.stderr); print(\'{"status": "complete"}\')'
    result = qualification.run_logged_process([sys.executable, '-c', child], log=log,
                                             env=dict(os.environ), timeout=10, json_output=True)
    assert result.returncode == 0
    assert json.loads(result.stdout) == {'status': 'complete'}
    assert 'diagnostic: real child' in log.read_text()
    assert result.stdout in log.read_text()


def test_nonzero_json_child_exit_is_not_hidden(tmp_path):
    result = qualification.run_logged_process(
        [sys.executable, '-c', 'import sys; print("{}" ); print("failed", file=sys.stderr); sys.exit(7)'],
        log=tmp_path / 'failure.log', env=dict(os.environ), timeout=10, json_output=True)
    assert result.returncode == 7
    assert 'failed' in (tmp_path / 'failure.log').read_text()


def test_historical_adapter_uses_equivalent_unprivileged_environment(monkeypatch):
    lab_spec = importlib.util.spec_from_file_location('lab', Path(__file__).resolve().parents[1] / 'scripts/verify_cyberrecon_lab.py')
    lab = importlib.util.module_from_spec(lab_spec)
    lab_spec.loader.exec_module(lab)
    monkeypatch.setenv('NMAP_PRIVILEGED', '1')
    monkeypatch.setenv('NMAP_UNPRIVILEGED', 'original')
    def historical_scanner(repository, project, target, ports=None):
        pass
    assert lab.lab_scan_options(historical_scanner, None) == {}
    assert os.environ['NMAP_UNPRIVILEGED'] == '1'
    assert 'NMAP_PRIVILEGED' not in os.environ
    def current_scanner(repository, project, target, nmap_unprivileged=False, nmap_diagnostic=None):
        pass
    callback = lambda record: None
    assert lab.lab_scan_options(current_scanner, callback) == {
        'nmap_unprivileged': True, 'nmap_diagnostic': callback}
