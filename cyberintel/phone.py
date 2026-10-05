"""Offline numbering-plan metadata, never device or subscriber tracking."""
import re

import phonenumbers
from phonenumbers import carrier, geocoder, timezone

from .models import Result, ValidationError

REFERENCE = "https://github.com/daviddrysdale/python-phonenumbers"


def estimate_phone_region(value: str, default_region: str = "") -> Result:
    value = value.strip()
    region = default_region.strip().upper()
    if region and region not in phonenumbers.SUPPORTED_REGIONS:
        raise ValidationError("Use a supported two-letter country code, such as IN, GB or US.")
    if not value or len(value) > 40 or not re.fullmatch(r"\+?[0-9 ()\-.]+", value):
        raise ValidationError("Enter a phone number using digits, an optional +, spaces or separators.")
    if not value.startswith("+") and not region:
        raise ValidationError("Use +country-code format or provide the number's country code (e.g. IN).")
    try:
        number = phonenumbers.parse(value, region or None)
    except phonenumbers.NumberParseException:
        raise ValidationError("The phone number could not be parsed.") from None
    if not phonenumbers.is_valid_number(number):
        raise ValidationError("Number is not valid under the installed numbering-plan metadata. No area estimate available.")
    normalized = phonenumbers.format_number(number, phonenumbers.PhoneNumberFormat.E164)
    region_code = phonenumbers.region_code_for_number(number) or ""
    country = geocoder.country_name_for_number(number, "en")
    area = geocoder.description_for_number(number, "en")
    # A mobile prefix may have no geographical association, or only a country name.
    granular_area = area if area and area != country else ""
    kind = phonenumbers.number_type(number)
    kinds = {getattr(phonenumbers.PhoneNumberType, name): name.lower().replace("_", " ")
             for name in ["FIXED_LINE", "MOBILE", "FIXED_LINE_OR_MOBILE", "TOLL_FREE", "PREMIUM_RATE", "SHARED_COST", "VOIP", "PERSONAL_NUMBER", "PAGER", "UAN", "VOICEMAIL", "UNKNOWN"]}
    zones = [zone for zone in timezone.time_zones_for_number(number) if zone != "Etc/Unknown"]
    data = {
        "record_kind": "inferred", "estimate_basis": "Public numbering-plan/prefix allocation metadata",
        "number_e164": normalized, "number_type": kinds.get(kind, "unknown"),
        "country_calling_code": "+" + str(number.country_code), "region_code": region_code or "unknown / non-geographic",
        "country_or_territory": country or "unavailable",
        "numbering_area": granular_area or "unavailable; no city/area estimate from this prefix",
        "estimate_precision": "numbering area only" if granular_area else "country/territory only" if country else "unavailable",
        "original_carrier": carrier.name_for_number(number, "en") or "unavailable",
        "associated_time_zones": zones,
        "metadata_version": phonenumbers.__version__, "device_location_available": False,
        "limitations": "Number allocation does not reveal a device's current or past location, subscriber identity, or whether the number is active. Portability, roaming and reassignment can invalidate carrier/area associations. Time zones are numbering-plan associations, not location observations. No coordinates are generated."
    }
    return Result("libphonenumber public numbering metadata", REFERENCE, normalized, data,
                  status="offline", freshness="bundled metadata")
