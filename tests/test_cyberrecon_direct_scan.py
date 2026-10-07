import pytest

from cyberrecon.storage import Repository


def test_direct_scan_context_preserves_authorization_and_history(tmp_path, monkeypatch):
    monkeypatch.setenv('QT_QPA_PLATFORM', 'offscreen')
    from PySide6.QtWidgets import QApplication, QPushButton
    from cyberrecon.gui import Window
    app = QApplication.instance() or QApplication([])
    repo = Repository(tmp_path)
    window = Window(repo)
    try:
        assert not any(button.text() == 'New project' for button in window.findChildren(QPushButton))
        window.target.setText('https://example.org/')
        with pytest.raises(ValueError, match='authorization'):
            window.scan_context()
        assert repo.projects() == []
        window.authority.setText('Own test fixture')
        identifier = window.scan_context()
        assert repo.scope(identifier).include == ('example.org',)
        assert window.scan_context() == identifier
        assert len(repo.projects()) == 1
        window.excludes.setText('example.org')
        with pytest.raises(ValueError, match='OUT OF SCOPE'):
            window.scan_context()
        assert len(repo.projects()) == 1
    finally:
        window.close()
        app.processEvents()
