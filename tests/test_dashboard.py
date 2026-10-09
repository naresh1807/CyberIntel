import json

import httpx
import pytest

from cyberrecon.dashboard import SECTIONS, applicable_ports, dashboard_rows, normalize_target, overview_html
from cyberrecon.scanner import scan
from cyberrecon.storage import Repository


@pytest.mark.parametrize('value,expected', [
    ('qualitythought.in', 'qualitythought.in'),
    (' https://qualitythought.in/a ', 'https://qualitythought.in/a'),
    ('192.0.2.1', '192.0.2.1'), ('2001:db8::1', '2001:db8::1'),
    ('http://[::1]:8080/', 'http://[::1]:8080/'),
])
def test_target_normalization(value, expected):
    assert normalize_target(value) == expected


@pytest.mark.parametrize('value', ['', '-sV', 'bad domain.in', 'ftp://example.org',
    'https://user:password@example.org', 'http://[bad', 'https://example.org:wrong',
    'example.org;id', 'https://example.org\\evil'])
def test_invalid_target(value):
    with pytest.raises(ValueError):
        normalize_target(value)


def test_no_implicit_nmap_ip_authorization():
    assert applicable_ports('qualitythought.in', '80') is None
    assert applicable_ports('https://qualitythought.in/', '80') is None
    assert applicable_ports('http://[::1]:8080', '8080') == '8080'


def test_dashboard_real_storage_partial_and_scope(tmp_path, monkeypatch):
    repo = Repository(tmp_path)
    project = repo.create_project('owned', ['127.0.0.1'], [], 'Owned fixture')
    requests = []
    def respond(request):
        requests.append(str(request.url))
        if request.url.path == '/robots.txt':
            raise httpx.ReadTimeout('fixture timeout')
        return httpx.Response(200, headers={'content-type': 'text/html'}, text='''
          <title>Owned fixture</title><meta name="generator" content="Fixture CMS">
          <script src="/jquery.min.js"></script><a href="https://outside.example/">outside</a>''')
    def missing(*args, **kwargs):
        raise FileNotFoundError('nmap unavailable')
    monkeypatch.setattr('cyberrecon.engines.port_scan', missing)
    identifier = scan(repo, project, 'http://127.0.0.1/', crawl=True, ports='80',
                      transport=httpx.MockTransport(respond))
    snapshot = repo.snapshot(identifier)
    rows = dashboard_rows(snapshot)
    assert snapshot['scan']['status'] == 'partial'
    assert any(row.get('title') == 'Owned fixture' for row in snapshot['http'])
    assert any(row.get('technology') == 'jquery' and row['confidence'] == 'candidate' for row in rows['technologies'])
    assert any(row.get('banner') == 'Fixture CMS' for row in rows['technologies'])
    assert rows['evidence'] and not rows['ports']
    assert all(url.startswith('http://127.0.0.1/') for url in requests)
    assert 'http://127.0.0.1/sitemap.xml' in requests
    assert 'No observations' in overview_html(snapshot)
    snapshot['scan']['target'] = '<script>bad</script>'
    assert '<script>' not in overview_html(snapshot)


def test_simple_gui_and_authorization_cancel(tmp_path, monkeypatch):
    monkeypatch.setenv('QT_QPA_PLATFORM', 'offscreen')
    from PySide6.QtWidgets import QApplication, QLineEdit, QInputDialog
    from PySide6.QtCore import QThreadPool
    from cyberrecon.gui import Window
    app = QApplication.instance() or QApplication([])
    window = Window(Repository(tmp_path))
    try:
        window.show()
        app.processEvents()
        assert window.navigation.count() == len(SECTIONS) == 13
        assert [field for field in window.findChildren(QLineEdit) if field.isVisible()] == [window.target]
        monkeypatch.setattr(QInputDialog, 'getText', lambda *args: ('', False))
        window.target.setText('qualitythought.in')
        window.start_scan()
        assert window.worker is None
        assert window.repo.projects() == []
        assert 'authorization reference required' in window.status.text()
    finally:
        window.close()
        QThreadPool.globalInstance().waitForDone(45000)
        app.processEvents()


def test_nmap_metadata_projection():
    from cyberintel.nmap_scan import parse_scan
    result = parse_scan(b'''<nmaprun version="7.99"><host starttime="10" endtime="11">
      <status state="up"/><address addr="127.0.0.1" addrtype="ipv4"/>
      <os><osmatch name="fixture hint" accuracy="90"/></os></host>
      <runstats><finished exit="success" elapsed="1.0"/></runstats></nmaprun>''')
    assert result['hosts'][0]['timing'] == {'starttime': '10', 'endtime': '11'}
    assert result['hosts'][0]['os_matches'][0]['accuracy'] == '90'
    assert result['completion']['exit'] == 'success'
    rows = dashboard_rows({'scan': {'warnings': []}, 'assets': [{'host': '127.0.0.1',
        'nmap_host': result['hosts'][0], 'nmap_completion': result['completion']}]})
    assert rows['nmap'][0]['nmap_host']['status'] == 'up'
