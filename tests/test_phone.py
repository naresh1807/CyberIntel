import json
import time

import phonenumbers
import pytest
from PySide6.QtWidgets import QApplication

from cyberintel.config import Config
from cyberintel.models import ValidationError
from cyberintel.phone import estimate_phone_region
from cyberintel.ui import MainWindow


def test_mobile_region_has_no_device_coordinates():
    # Library-provided example number, not a queried subscriber.
    number = phonenumbers.example_number_for_type("IN", phonenumbers.PhoneNumberType.MOBILE)
    value = phonenumbers.format_number(number, phonenumbers.PhoneNumberFormat.E164)
    result = estimate_phone_region(value)
    assert result.data["region_code"] == "IN"
    assert result.data["record_kind"] == "inferred"
    assert result.data["device_location_available"] is False
    assert result.status == "offline"
    assert "latitude" not in result.data and "longitude" not in result.data
    assert result.data["metadata_version"] == phonenumbers.__version__


def test_national_number_requires_explicit_region():
    with pytest.raises(ValidationError, match="country"):
        estimate_phone_region("0431234567")
    result = estimate_phone_region("0431234567", "ch")
    assert result.query == "+41431234567"
    assert result.data["numbering_area"] == "Zurich"
    assert result.data["estimate_precision"] == "numbering area only"


@pytest.mark.parametrize("value,region", [("123", "IN"), ("hello", ""), ("+911234567890 ext 12", ""), ("+41431234567", "XX"), ("", "IN")])
def test_invalid_inputs(value, region):
    with pytest.raises(ValidationError):
        estimate_phone_region(value, region)


def test_phone_ui_worker_saves_case_finding(session, tmp_path):
    app = QApplication.instance() or QApplication([])
    window = MainWindow(Config(tmp_path), session)
    case = session.create_case("Numbering metadata test")
    window.reload_cases(case)
    window.phone_number.setText("+41431234567")
    window.run_phone_estimate()
    deadline = time.monotonic() + 10
    while window.busy and time.monotonic() < deadline:
        app.processEvents()
        time.sleep(.01)
    assert not window.busy
    result = window.last_results["phone"]
    assert result.data["record_kind"] == "inferred"
    finding = session.rows("findings", case)[0]
    assert finding["module"] == "phone"
    assert json.loads(finding["result"])["data"]["device_location_available"] is False
    window.close()
