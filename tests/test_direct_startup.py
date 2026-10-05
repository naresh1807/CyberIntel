import pytest
from PySide6.QtWidgets import QApplication

from cyberintel import app as desktop


def test_main_opens_workspace_without_account_dialog(tmp_path, monkeypatch):
    qt = QApplication.instance() or QApplication([])
    monkeypatch.setattr(desktop, "QApplication", lambda _: qt)
    monkeypatch.setattr(QApplication, "exec", lambda self: 0)
    monkeypatch.setattr("sys.argv", ["cyberintel", "--data-dir", str(tmp_path)])
    opened = []
    class Window:
        def __init__(self, config, session):
            self.session = session
        def show(self):
            assert not self.session.store.initialized()
            self.session.create_case("Direct startup works")
            opened.append(self.session.actor)
    monkeypatch.setattr(desktop, "MainWindow", Window)
    with pytest.raises(SystemExit) as result:
        desktop.main()
    assert result.value.code == 0
    assert opened == ["local-workspace"]
