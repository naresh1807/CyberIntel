import base64
import json

import httpx
import pytest
from PySide6.QtWidgets import QApplication

from cyberintel.config import Config
from cyberintel.connectors import Collector
from cyberintel.ui import MainWindow

KEYS = {"twilio_account_sid": "AC" + "0" * 32, "twilio_key_sid": "SK" + "1" * 32,
        "twilio_key_secret": "synthetic-test-secret"}


def collector(session, handler, keys=KEYS):
    return Collector(Config(session.store.home), session.store, keys=keys,
                     transport=httpx.MockTransport(handler), sleeper=lambda _: None)


def test_twilio_authentication_allowlist_and_optional_carrier(session):
    def handler(request):
        assert request.url.host == "lookups.twilio.com"
        auth = request.headers["Authorization"].removeprefix("Basic ")
        assert base64.b64decode(auth).decode() == KEYS["twilio_key_sid"] + ":" + KEYS["twilio_key_secret"]
        line = {"type": "mobile", "carrier_name": "Synthetic carrier", "error_code": None}
        return httpx.Response(200, json={"valid": True, "phone_number": "+14155552671", "country_code": "US",
            "line_type_intelligence": line, "caller_name": {"caller_name": "Excluded"}, "account_sid": KEYS["twilio_account_sid"]})
    client = collector(session, handler)
    basic = client.collect("twilio_phone", "+14155552671")
    assert basic.status == "live" and "line_type_intelligence" not in basic.data
    paid = client.collect("twilio_phone_carrier", "+14155552671")
    assert paid.data["line_type_intelligence"]["type"] == "mobile"
    serialized = json.dumps(paid.to_dict())
    assert "Excluded" not in serialized and KEYS["twilio_key_secret"] not in serialized
    assert KEYS["twilio_account_sid"] not in serialized


def test_twilio_invalid_target_and_missing_keys_make_no_request(session):
    client = collector(session, lambda _: pytest.fail("No request expected"), keys={})
    assert client.collect("twilio_phone", "not-a-number").status == "unavailable"
    assert "configure" in client.collect("twilio_phone", "+14155552671").error.lower()


@pytest.mark.parametrize("payload", [{}, {"valid": "true"}, {"valid": True, "line_type_intelligence": []}])
def test_twilio_malformed_response(session, payload):
    result = collector(session, lambda _: httpx.Response(200, json=payload)).collect("twilio_phone", "+14155552671")
    assert result.status == "unavailable" and result.data is None


def test_twilio_carrier_error_remains_visible(session):
    result = collector(session, lambda _: httpx.Response(200, json={"valid": True,
        "line_type_intelligence": {"error_code": 60601}})).collect("twilio_phone_carrier", "+14155552671")
    assert result.data["line_type_intelligence"]["error_code"] == 60601
    assert "warning" in result.data


def test_phone_ui_requires_authorization_and_saves_case(session, monkeypatch):
    app = QApplication.instance() or QApplication([])
    window = MainWindow(Config(session.store.home), session)
    errors = []
    monkeypatch.setattr(window, "error", errors.append)
    window.run_twilio_phone()
    assert errors and not window.busy and not window.phone_paid_carrier.isChecked()
    case = session.create_case("Twilio synthetic lookup")
    window.reload_cases()
    window.case_selector.setCurrentIndex(window.case_selector.findData(case))
    window.collector = collector(session, lambda request: httpx.Response(200, json={"valid": True, "phone_number": "+14155552671"}))
    window.phone_number.setText("+14155552671")
    window.phone_authorized.setChecked(True)
    monkeypatch.setattr(window, "start_job", lambda label, task, done: done(task()))
    window.run_twilio_phone()
    assert window.last_results["phone"].source == "Twilio Lookup"
    assert session.rows("findings", case)[0]["module"] == "phone"
    assert all(name in window.key_fields for name in KEYS)
    window.close()
