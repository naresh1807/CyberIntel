"""Offline matching against authorized contact/profile records; no account enumeration."""
import re
from pathlib import Path
from urllib.parse import urlsplit

from .analysis import read_table, sha256
from .connectors import email
from .models import Result, ValidationError

PLATFORMS = {"linkedin.com": "LinkedIn", "facebook.com": "Facebook", "instagram.com": "Instagram",
             "x.com": "X", "twitter.com": "X", "tiktok.com": "TikTok", "github.com": "GitHub",
             "youtube.com": "YouTube"}


def normalize_contact(value, kind):
    if kind == "email":
        return email(value).casefold()
    if kind == "phone":
        value = value.strip()
        if not re.fullmatch(r"\+[0-9 ()\-.]+", value):
            raise ValidationError("Phone lookup requires an international number beginning with +country code.")
        value = re.sub(r"[ ()\-.]", "", value)
        if not re.fullmatch(r"\+[1-9][0-9]{6,14}", value):
            raise ValidationError("Use +country code followed by 7–15 digits.")
        return value
    raise ValidationError("Choose email or phone lookup.")


def profile_link(value):
    try:
        parts = urlsplit(value.strip())
        if (parts.scheme != "https" or parts.port not in (None, 443) or parts.username or parts.password
                or parts.query or parts.fragment or not parts.hostname or len(value) > 2048
                or any(character.isspace() or ord(character) < 32 for character in value)):
            raise ValueError()
        host = parts.hostname.lower()
        platform = next((name for domain, name in PLATFORMS.items() if host in {domain, "www." + domain}), None)
        if not platform or parts.path in {"", "/"}:
            raise ValueError()
    except ValueError:
        raise ValidationError("Use an HTTPS profile link on a supported platform, without credentials, query or fragment.") from None
    return platform, parts._replace(netloc=host).geturl()


def lookup_profiles(path, value, kind="email", authorized=False, data_kind="actual"):
    if not authorized:
        raise ValidationError("Confirm you are authorized to use this contact directory for profile lookup.")
    if data_kind not in {"actual", "inferred", "synthetic"}:
        raise ValidationError("Invalid provenance kind.")
    query = normalize_contact(value, kind)
    frame = read_table(path)
    if "profile_url" not in frame.columns or kind not in frame.columns:
        raise ValidationError(f"Directory needs profile_url and {kind} columns. Optional: display_name.")
    matches, warnings = {}, []
    invalid_contacts = 0
    for offset, row in enumerate(frame.to_dict("records"), 2):
        supplied = row.get(kind, "")
        if not supplied:
            continue
        try:
            candidate = normalize_contact(supplied, kind)
        except ValidationError:
            invalid_contacts += 1
            continue
        if candidate != query:
            continue
        try:
            platform, link = profile_link(row.get("profile_url", ""))
        except ValidationError:
            warnings.append(f"Matched source row {offset} has an unsupported or invalid profile link; omitted.")
            continue
        name = row.get("display_name", "")
        key = (link, name)
        if key in matches:
            matches[key]["source_rows"].append(offset)
        else:
            matches[key] = {"platform": platform, "profile_url": link, "display_name": name,
                            "match_basis": "Supplied directory " + kind + " match", "source_rows": [offset],
                            "ownership_confirmed": False, "profile_availability": "not checked"}
    records = sorted(matches.values(), key=lambda row: (row["platform"], row["profile_url"], row["display_name"]))
    if invalid_contacts:
        warnings.append(f"Skipped {invalid_contacts} malformed {kind} entries; directory coverage may be incomplete.")
    return Result("Authorized contact directory", Path(path).name, query,
                  {"records": records, "match_count": len(records), "lookup_kind": kind,
                   "file_sha256": sha256(path), "provenance_kind": data_kind,
                   "directory_row_count": len(frame), "warnings": warnings,
                   "note": "Offline matches against supplied records only. No social platform was contacted. Links, identity, ownership and current availability are not independently verified. No matches means none in this directory, not absence of an account."},
                  status="synthetic" if data_kind == "synthetic" else "offline", error="; ".join(warnings) or None)
