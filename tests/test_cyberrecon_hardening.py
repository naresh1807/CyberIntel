import hashlib
import json
import os
import sqlite3
import sys
import threading

import httpx
import pytest

from cyberrecon.cli import main
from cyberrecon.doctor import tool_status
from cyberrecon.engines import ToolError, content_scan, fingerprint, run_process
from cyberrecon.importers import import_jsonl
from cyberrecon.network import ScopedHTTP
from cyberrecon.scanner import scan
from cyberrecon.scope import Scope
from cyberrecon.storage import Repository, compare_snapshots


def workspace(tmp_path):
    repo = Repository(tmp_path / 'workspace')
    project = repo.create_project('Fixture', ['example.org', '192.0.2.4'], authority='Owned mock fixture')
    return repo, project


@pytest.mark.parametrize('destination', ['https://example.org:444/', 'http://example.org/', 'https://other.org/'])
def test_credentials_never_cross_origin(destination):
    calls = []
    def handler(request):
        calls.append(request)
        return httpx.Response(302, headers={'location': destination})
    client = ScopedHTTP(lambda: Scope(('example.org', 'other.org')), transport=httpx.MockTransport(handler), rate=10)
    with pytest.raises(ValueError):
        client.fetch('https://example.org/', request_headers={'Authorization': 'Bearer PRIVATE_FIXTURE'})
    assert len(calls) == 1


def test_explicit_default_port_same_origin_is_allowed():
    calls = []
    def handler(request):
        calls.append(request)
        return httpx.Response(302, headers={'location': 'https://example.org:443/next'}) if len(calls) == 1 else httpx.Response(200)
    client = ScopedHTTP(lambda: Scope(('example.org',)), transport=httpx.MockTransport(handler), rate=10)
    assert client.fetch('https://example.org/', request_headers={'Authorization': 'Bearer fixture'})['status_code'] == 200
    assert len(calls) == 2


@pytest.mark.parametrize('target', ['-oX /tmp/x', 'example.org;touch /tmp/x', 'example.org\nattacker.org', 'https://user:secret@example.org/', 'https://example.org:99999/'])
def test_malicious_target_rejected(target):
    with pytest.raises(ValueError):
        Scope(('example.org',)).require(target)


def test_process_argv_preserves_literal_shell_metacharacters(tmp_path):
    marker = tmp_path / 'injected'
    argument = f'$(touch {marker});`touch {marker}`'
    raw = run_process([sys.executable, '-c', 'import sys; print(sys.argv[1])', argument])
    assert raw.decode().strip() == argument
    assert not marker.exists()


@pytest.mark.parametrize('channel', ['stdout', 'stderr'])
def test_process_final_output_limit(channel):
    with pytest.raises(ToolError) as error:
        run_process([sys.executable, '-c', f'import sys; sys.{channel}.write("x"*4096)'], max_output=1024)
    assert error.value.code == 'output_limit'


def test_process_file_limit(tmp_path):
    path = tmp_path / 'tool.xml'
    with pytest.raises(ToolError) as error:
        run_process([sys.executable, '-c', 'import pathlib,sys; pathlib.Path(sys.argv[1]).write_bytes(b"x"*4096)', str(path)],
                    output_paths=(path,), max_output=1024)
    assert error.value.code == 'output_limit'


def test_process_timeout_and_pre_cancel():
    with pytest.raises(ToolError) as error:
        run_process([sys.executable, '-c', 'import time; time.sleep(10)'], timeout=.1)
    assert error.value.code == 'timeout'
    cancel = threading.Event(); cancel.set()
    with pytest.raises(ToolError) as error:
        run_process([sys.executable, '-c', 'raise AssertionError("must not run")'], cancel=cancel)
    assert error.value.code == 'cancelled'


@pytest.mark.parametrize('args', ['echo dangerous', [], [sys.executable, '\x00']])
def test_process_invalid_argv(args):
    with pytest.raises(ValueError):
        run_process(args)


@pytest.mark.parametrize('adapter', ['fingerprint', 'content'])
def test_native_adapters_enforce_resolved_ip_exclusions(adapter, monkeypatch):
    import socket
    monkeypatch.setattr('cyberrecon.network.socket.getaddrinfo', lambda *a, **kw:
                        [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('8.8.8.8', 443))])
    monkeypatch.setattr('cyberrecon.engines.run_process', lambda *a, **kw: pytest.fail('External active adapter must not run'))
    scope = Scope(('example.org',), ('8.8.8.8',))
    with pytest.raises(ValueError, match='explicitly excluded'):
        if adapter == 'fingerprint': fingerprint('https://example.org', scope)
        else: content_scan('https://example.org', scope, ['admin'])


def test_managed_directory_symlinks_cannot_redirect_writes(tmp_path):
    repo, project = workspace(tmp_path)
    outside = tmp_path / 'outside'; outside.mkdir()
    (repo.home / 'scans').symlink_to(outside, target_is_directory=True)
    with pytest.raises(ValueError, match='symlinks'):
        repo.start_scan(project, 'example.org', {})
    assert repo.scans(project) == []
    assert list(outside.iterdir()) == []


def test_evidence_directory_symlink_rejected(tmp_path):
    repo, project = workspace(tmp_path)
    identifier = repo.start_scan(project, 'example.org', {})
    outside = tmp_path / 'outside'; outside.mkdir()
    (repo.home / 'scans' / identifier / 'evidence').symlink_to(outside, target_is_directory=True)
    with pytest.raises(ValueError, match='symlinks'):
        repo.evidence(identifier, 'nmap.xml', b'fixture')
    assert list(outside.iterdir()) == []


def test_database_sidecar_symlink_rejected(tmp_path):
    home = tmp_path / 'workspace'; home.mkdir()
    outside = tmp_path / 'outside'; outside.write_text('preserve')
    (home / 'cyberrecon.db-wal').symlink_to(outside)
    with pytest.raises(ValueError, match='sidecars'):
        Repository(home)
    assert outside.read_text() == 'preserve'


def test_existing_workspace_permissions_tightened(tmp_path):
    repo, _ = workspace(tmp_path)
    repo.home.chmod(0o755); repo.path.chmod(0o644)
    Repository(repo.home)
    assert repo.home.stat().st_mode & 0o777 == 0o700
    assert repo.path.stat().st_mode & 0o777 == 0o600


def test_provenance_and_identifiers_survive_duplicate_sources(tmp_path):
    repo, project = workspace(tmp_path)
    identifier = repo.start_scan(project, 'example.org', {})
    first = repo.save(identifier, 'assets', 'example.org', {'active_verified': True}, 'native')
    last = repo.save(identifier, 'assets', 'example.org', {'key': 'attacker', 'active_verified': False}, 'import')
    assert last['key'] == 'example.org'
    assert last['sources'] == ['import', 'native']
    assert last['first_seen'] == first['first_seen']
    assert last['asset_id'] == first['asset_id']
    assert last['active_verified']
    assert len(repo.snapshot(identifier)['assets']) == 1


def test_dns_import_normalizes_and_rejects_partial_rows(tmp_path):
    repo, project = workspace(tmp_path)
    path = tmp_path / 'dns.jsonl'
    path.write_text(json.dumps({'host': 'example.org', 'a': ['192.0.2.4'], 'aaaa': ['bad']}) + '\n' +
                    json.dumps({'host': 'example.org', 'a': ['192.0.2.4', '192.0.2.4']}) + '\n')
    identifier = import_jsonl(repo, project, 'example.org', 'dnsx', path)
    rows = repo.snapshot(identifier)['dns']
    assert len(rows) == 1
    assert rows[0]['key'] == 'example.org:A:' + hashlib.sha256(b'192.0.2.4').hexdigest()
    assert any('Rejected 1' in warning for warning in repo.snapshot(identifier)['scan']['warnings'])


def test_explicit_recovery_preserves_data_and_is_idempotent(tmp_path, capsys):
    repo, project = workspace(tmp_path)
    identifier = repo.start_scan(project, 'example.org', {})
    repo.save(identifier, 'assets', 'example.org', {}, 'fixture')
    assert main(['--home', str(repo.home), 'recover', project]) == 0
    assert identifier in capsys.readouterr().out
    assert repo.snapshot(identifier)['scan']['status'] == 'interrupted'
    assert len(repo.snapshot(identifier)['assets']) == 1
    assert repo.recover(project) == []
    with repo.connection() as db:
        assert db.execute('PRAGMA integrity_check').fetchone()[0] == 'ok'
        assert not db.execute('PRAGMA foreign_key_check').fetchall()


def test_keyboard_interrupt_cleans_scan(tmp_path, monkeypatch):
    repo, project = workspace(tmp_path)
    monkeypatch.setattr('cyberrecon.scanner.ScopedHTTP.fetch', lambda *a, **kw: (_ for _ in ()).throw(KeyboardInterrupt()))
    with pytest.raises(KeyboardInterrupt):
        scan(repo, project, 'example.org', transport=httpx.MockTransport(lambda req: httpx.Response(200)))
    assert repo.scans(project)[0]['status'] == 'cancelled'


def test_failed_optional_tool_is_degraded_and_structured(tmp_path, monkeypatch):
    repo, project = workspace(tmp_path)
    monkeypatch.setattr('cyberrecon.engines.passive_domains', lambda *a: (_ for _ in ()).throw(ToolError('tool_missing', 'subfinder')))
    identifier = scan(repo, project, 'example.org', passive='subfinder', transport=httpx.MockTransport(lambda req: httpx.Response(200)))
    snapshot = repo.snapshot(identifier)
    assert snapshot['scan']['status'] == 'partial'
    assert snapshot['http']
    assert snapshot['errors'][0]['code'] == 'tool_missing'


def test_exception_payload_secrets_not_persisted(tmp_path, monkeypatch):
    repo, project = workspace(tmp_path)
    monkeypatch.setattr('cyberrecon.scanner.ScopedHTTP.fetch', lambda *a, **kw: (_ for _ in ()).throw(RuntimeError('token=PRIVATE_SECRET')))
    identifier = scan(repo, project, 'example.org', transport=httpx.MockTransport(lambda req: httpx.Response(200)))
    assert 'PRIVATE_SECRET' not in json.dumps(repo.snapshot(identifier))


@pytest.mark.parametrize('name,output,status', [('nmap', b'Nmap version 7.95', 'READY'), ('amass', b'v4.2.0', 'UNSUPPORTED'),
                                             ('httpx', b'Usage: Python HTTPX CLI', 'REVIEW'), ('ffuf', b'ffuf version: 2.1.0', 'READY')])
def test_doctor_versions(name, output, status, monkeypatch):
    monkeypatch.setattr('cyberrecon.doctor.shutil.which', lambda name: sys.executable)
    monkeypatch.setattr('cyberrecon.doctor.run_process', lambda *a, **kw: output)
    assert tool_status(name, 'fixture')['status'] == status


def test_doctor_failure_is_actionable_without_output(monkeypatch):
    monkeypatch.setattr('cyberrecon.doctor.shutil.which', lambda name: sys.executable)
    monkeypatch.setattr('cyberrecon.doctor.run_process', lambda *a, **kw: (_ for _ in ()).throw(ToolError('timeout', 'nmap')))
    assert tool_status('nmap', 'fixture')['status'] == 'TIMEOUT'


def test_doctor_wordlist_and_workspace_no_mutations(tmp_path, monkeypatch):
    from cyberrecon.doctor import doctor
    monkeypatch.setattr('cyberrecon.doctor.tool_status', lambda *a: {'status': 'OPTIONAL'})
    home = tmp_path / 'not-created'
    result = doctor(home, tmp_path / 'missing.txt')
    assert result['configuration']['wordlist'] == 'MISSING_OR_INVALID'
    assert not home.exists()


def test_resolution_deadline_and_cancel(monkeypatch):
    from cyberrecon.network import resolve_addresses
    gate = threading.Event()
    monkeypatch.setattr('cyberrecon.network.socket.getaddrinfo', lambda *a, **kw: gate.wait(2) or [])
    try:
        with pytest.raises(TimeoutError):
            resolve_addresses('example.org.', 443, timeout=.01)
        cancel = threading.Event(); cancel.set()
        with pytest.raises(ValueError, match='cancelled'):
            resolve_addresses('example.org.', 443, cancel=cancel)
    finally:
        gate.set()


def test_scope_reload_after_dns_before_connection(monkeypatch):
    import socket
    state = [Scope(('example.org',))]
    def resolve(*a, **kw):
        state[0] = Scope(('other.org',))
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('8.8.8.8', 443))]
    monkeypatch.setattr('cyberrecon.network.socket.getaddrinfo', resolve)
    with pytest.raises(ValueError, match='OUT OF SCOPE'):
        ScopedHTTP(lambda: state[0]).fetch('https://example.org/')


def test_directed_graph_click_details_are_escaped(tmp_path):
    from cyberrecon.graph import export_graph
    repo, project = workspace(tmp_path)
    identifier = repo.start_scan(project, 'example.org', {})
    repo.save(identifier, 'assets', 'example.org', {'note': '</script><script>alert(123456)</script>'}, 'fixture')
    repo.save(identifier, 'relationships', 'edge', {'from_node': 'host:example.org', 'to_node': 'url:https://example.org/', 'relation': 'serves'}, 'fixture')
    path = tmp_path / 'graph.html'
    export_graph(repo.snapshot(identifier), path)
    html = path.read_text()
    assert 'plotly_click' in html
    assert 'textContent = JSON.stringify' in html
    assert '</script><script>alert(123456)' not in html
    assert 'observations' in html and 'incoming' in html and 'outgoing' in html


def test_concurrent_sources_and_reads_preserve_unique_record(tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    repo, project = workspace(tmp_path)
    identifier = repo.start_scan(project, 'example.org', {})
    def write(index):
        repo.save(identifier, 'assets', 'example.org', {'host': 'example.org'}, f'source{index}')
        return repo.snapshot(identifier)
    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(write, range(12)))
    rows = repo.snapshot(identifier)['assets']
    assert len(rows) == 1 and len(rows[0]['sources']) == 12


def test_doctor_missing_and_permission(tmp_path, monkeypatch):
    monkeypatch.setenv('PATH', str(tmp_path))
    assert tool_status('nmap', 'fixture')['status'] == 'OPTIONAL'
    (tmp_path / 'nmap').write_text('fixture')
    (tmp_path / 'nmap').chmod(0o600)
    assert tool_status('nmap', 'fixture')['status'] == 'PERMISSION_DENIED'


def test_amass_unsupported_version_never_enumerates(monkeypatch):
    calls = []
    def run(args, **kwargs):
        calls.append(args)
        return b'v4.2.0'
    monkeypatch.setattr('cyberrecon.engines.run_process', run)
    from cyberrecon.engines import passive_domains
    with pytest.raises(ValueError, match='v3 CLI'):
        passive_domains('amass', 'example.org', Scope(('example.org',)))
    assert calls == [['amass', '-version']]


@pytest.mark.parametrize('target', ['https://exam\tple.org/', 'https://example.org/\r\nheader', 'exam\x7fple.org'])
def test_url_controls_rejected_before_normalization(target):
    with pytest.raises(ValueError):
        Scope(('example.org',)).require(target)


def test_swagger_basepath_parameters_and_security_override():
    from cyberrecon.api import extract
    response = {'url': 'https://example.org/swagger.json', 'status_code': 200, 'truncated': False, 'headers': {'content-type': 'application/json'}}
    body = json.dumps({'swagger':'2.0', 'host':'example.org', 'basePath':'/v2', 'security':[{'key':[]}],
                       'paths':{'/users':{'parameters':[{'name':'id'}], 'get':{'security':[]}}}})
    rows = extract(response, body, Scope(('example.org',)))
    endpoint = next(row for row in rows if row.get('documentation_url'))
    assert endpoint['url'] == 'https://example.org/v2/users'
    assert endpoint['parameter_names'] == ['id']
    assert endpoint['declares_security'] is False


def test_doctor_discovers_worker_used_by_orchestrator(monkeypatch):
    monkeypatch.setattr('cyberrecon.doctor.shutil.which', lambda name: None)
    monkeypatch.setattr('cyberrecon.go_worker.worker_path', lambda: sys.executable)
    monkeypatch.setattr('cyberrecon.doctor.run_process', lambda *a, **kw: b'cyberrecon-dns 0.2.0')
    result = tool_status('cyberrecon-dns', 'fixture')
    assert result['installed'] and not result['on_path']
    assert result['status'] == 'READY'


def test_doctor_dependency_import_and_version_problems(monkeypatch, tmp_path):
    from cyberrecon.doctor import doctor
    monkeypatch.setattr('cyberrecon.doctor.tool_status', lambda *a: {'status': 'OPTIONAL'})
    monkeypatch.setattr('cyberrecon.doctor.importlib.util.find_spec', lambda name: object())
    monkeypatch.setattr('cyberrecon.doctor.importlib.metadata.version', lambda name: '0.1.0' if name == 'httpx' else '6.8.0')
    def imported(module):
        if module == 'PySide6.QtWidgets': raise ImportError('PRIVATE_FIXTURE must not appear')
    monkeypatch.setattr('cyberrecon.doctor.importlib.import_module', imported)
    report = doctor(tmp_path)
    assert report['dependencies']['httpx']['status'] == 'UNSUPPORTED'
    assert report['dependencies']['PySide6']['status'] == 'BROKEN'
    assert 'PRIVATE_FIXTURE' not in json.dumps(report)


def test_report_export_cannot_replace_managed_raw_evidence(tmp_path):
    repo, project = workspace(tmp_path)
    identifier = repo.start_scan(project, 'example.org', {})
    evidence = repo.evidence(identifier, 'assets.json', b'original raw evidence')
    directory = (repo.home / evidence['path']).parent
    with pytest.raises(ValueError, match='evidence'):
        repo.export_json(identifier, directory)
    assert (directory / 'assets.json').read_bytes() == b'original raw evidence'


def test_failed_observation_update_rolls_back_and_foreign_keys_hold(tmp_path):
    repo, project = workspace(tmp_path)
    identifier = repo.start_scan(project, 'example.org', {})
    repo.save(identifier, 'assets', 'example.org', {'host':'example.org'}, 'fixture')
    with pytest.raises(ValueError):
        repo.save(identifier, 'assets', 'example.org', {'bad':float('nan')}, 'bad')
    assert repo.snapshot(identifier)['assets'][0]['sources'] == ['fixture']
    with pytest.raises(sqlite3.IntegrityError):
        repo.save('missing-scan', 'assets', 'example.org', {}, 'fixture')


def test_future_schema_rejected_without_downgrade(tmp_path):
    repo, project = workspace(tmp_path)
    with repo.connection() as db: db.execute('PRAGMA user_version=4')
    with pytest.raises(ValueError, match='newer'):
        Repository(repo.home)
    with sqlite3.connect(repo.path) as db: assert db.execute('PRAGMA user_version').fetchone()[0] == 4


@pytest.mark.parametrize('family,value,expected', [('CNAME','ALIAS.Example.org.', {'value':'alias.example.org'}),
    ('NS','NS.Example.org.', {'value':'ns.example.org'}), ('MX','10 Mail.Example.org.', {'value':'mail.example.org','preference':10}),
    ('MX','0 .', {'value':'.','preference':0}), ('AAAA','2001:0db8::1', {'value':'2001:db8::1'})])
def test_dns_canonical_rdata(family, value, expected):
    from cyberrecon.normalization import dns_attributes, dns_key
    assert dns_attributes(family, value) == expected
    assert dns_key('example.org', family, expected['value']).startswith('example.org:' + family + ':')


def test_imported_cname_native_fact_deduplicates(tmp_path):
    from cyberrecon.normalization import dns_attributes, dns_key
    repo, project = workspace(tmp_path)
    path = tmp_path / 'dns.jsonl'; path.write_text(json.dumps({'host':'example.org', 'cname':['ALIAS.Example.org.']})+'\n')
    identifier = import_jsonl(repo, project, 'example.org', 'dnsx', path)
    value = dns_attributes('CNAME', 'alias.example.org.')
    repo.save(identifier, 'dns', dns_key('example.org', 'CNAME', value['value']), {'host':'example.org','type':'CNAME',**value}, 'native DNS')
    rows = repo.snapshot(identifier)['dns']
    assert len(rows) == 1
    assert rows[0]['sources'] == ['dnsx imported JSONL', 'native DNS']
