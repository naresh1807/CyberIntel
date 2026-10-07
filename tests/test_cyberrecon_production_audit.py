import json
import subprocess
import sys

import httpx
import pytest

from cyberrecon.doctor import doctor, tool_status
from cyberrecon.intelligence import advisory_cvss, enrich_cves, normalized_cpe
from cyberrecon.network import clean_url
from cyberrecon.scope import Scope
from cyberrecon.storage import Repository


@pytest.mark.parametrize('value,expected', [
    ('https://EXAMPLE.org.:443/path?token=secret', 'https://example.org/path?token='),
    ('http://example.org:80/', 'http://example.org/'),
    ('https://[2001:0db8:0:0::1]:443/', 'https://[2001:db8::1]/'),
    ('https://bücher.example/', 'https://xn--bcher-kva.example/'),
])
def test_canonical_url_aliases(value, expected):
    assert clean_url(value) == expected
    assert clean_url(expected) == expected


@pytest.mark.parametrize('value', ['https://example.org:0/', 'https://example.org/a\x7f', 'ftp://example.org/', 'https://example.org:65536/'])
def test_malformed_urls_rejected(value):
    with pytest.raises(ValueError): clean_url(value)
    if ':0/' in value:
        with pytest.raises(ValueError): Scope(('example.org',)).require(value)


@pytest.mark.parametrize('value,allowed', [('2001:db8::1',True),('2001:db8::2',False),('2001:db9::1',False),
                                         ('bücher.example',True),('a.xn--bcher-kva.example',False)])
def test_ipv6_idn_scope_exclusions(value, allowed):
    scope = Scope(('2001:db8::/64','bücher.example'), ('2001:db8::2',))
    assert scope.allows(value) is allowed


def test_doctor_executable_paths_and_minimum(monkeypatch):
    monkeypatch.setattr('cyberrecon.doctor.shutil.which', lambda name: sys.executable)
    monkeypatch.setattr('cyberrecon.doctor.run_process', lambda *a, **kw: b'Nmap version 7.95')
    result = tool_status('nmap','fixture')
    assert result['path'] == sys.executable
    assert result['minimum_supported_version'] == '7.0'


def test_doctor_rejects_unsafe_db_without_writing(tmp_path, monkeypatch):
    monkeypatch.setattr('cyberrecon.doctor.tool_status', lambda *a: {'status':'OPTIONAL'})
    outside = tmp_path / 'outside'; outside.write_bytes(b'unchanged')
    home = tmp_path / 'workspace'; home.mkdir()
    (home / 'cyberrecon.db-wal').symlink_to(outside)
    result = doctor(home)
    assert result['configuration']['database'] == 'UNSAFE_DATABASE_PATH'
    assert outside.read_bytes() == b'unchanged'
    assert not (home / 'cyberrecon.db').exists()
    (home / 'cyberrecon.db-wal').unlink()
    (home / 'cyberrecon.db').write_bytes(b'not a database')
    assert doctor(home)['configuration']['database'] == 'INVALID_DATABASE_HEADER'


def test_nvd_bad_entries_do_not_discard_valid_candidates(tmp_path):
    repo = Repository(tmp_path)
    project = repo.create_project('Fixture',['example.org'],authority='Own mock fixture')
    scan = repo.start_scan(project,'example.org',{})
    repo.save(scan,'technologies','nginx',{'cpe':[None,'cpe:/a:nginx:nginx:1.24.0']},'fixture')
    cvss = {'cvssMetricV31':[{'source':'nvd@nist.gov','type':'Primary','cvssData':{
        'version':'3.1','baseScore':9.8,'vectorString':'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'}}]}
    transport = httpx.MockTransport(lambda request: httpx.Response(200,json={'totalResults':3,'vulnerabilities':[
        {'cve':{'id':None}}, None, {'cve':{'id':'CVE-2026-12345','descriptions':None,'metrics':cvss}}]}))
    warnings = enrich_cves(repo,scan,transport=transport)
    finding = repo.snapshot(scan)['findings'][0]
    assert finding['advisory_cvss'][0]['base_score'] == 9.8
    assert not finding['confirmed_vulnerability']
    assert finding['risk_status'] == 'POTENTIALLY_AFFECTED'
    assert any('2 malformed' in warning for warning in warnings)
    assert normalized_cpe(None) is None
    assert advisory_cvss({'metrics':{'cvssMetricV31':[{'cvssData':{'baseScore':float('nan'),'vectorString':'bad'}}]}}) == []


def test_primary_module_entry_point():
    result = subprocess.run([sys.executable,'-m','cyberrecon','--version'],capture_output=True,text=True,timeout=10)
    assert result.returncode == 0 and result.stdout.strip() == '0.2.0'


def test_service_technology_is_connected_in_graph(tmp_path, monkeypatch):
    from cyberrecon.scanner import scan
    repo = Repository(tmp_path)
    project = repo.create_project('Fixture',['192.0.2.4'],authority='Own mock fixture')
    row = {'ip':'192.0.2.4','protocol':'tcp','port':443,'state':'open','service':'https','product':'nginx','version':'1.24.0','cpe':[]}
    monkeypatch.setattr('cyberrecon.engines.port_scan',lambda *a: ({'records':[row],'hosts':[]},b'fixture XML'))
    identifier = scan(repo,project,'192.0.2.4',ports='443',transport=httpx.MockTransport(lambda request: httpx.Response(200)))
    assert any(edge['from_node']=='service:192.0.2.4:tcp:443:https' and edge['to_node']=='technology:192.0.2.4:tcp:443'
               for edge in repo.snapshot(identifier)['relationships'])
