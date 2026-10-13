# Proprietary — Copyright (c) 2026 2351485 ALBERTA INC. All rights reserved.
#
# This file is part of the proprietary core (the import engine).
# It is NOT licensed under Apache 2.0, MIT, or any other open licence.
# No patent licence is granted by this file; all patent rights are
# expressly reserved. See LICENSING.md for the licence map.
#
# The import *format definitions* (which columns each exporter emits)
# are documented in LICENSING.md and are Apache 2.0 material; the
# parsing / dedupe / conflict engine in this file is proprietary.

"""Import engine: browsers (all types), password managers, generic CSV.

Every parser returns a list of plain entry records (service, username,
password, url, notes, totp_secret, tags, favourite). Detection is by
header signature (CSV), top-level structure (JSON) or root element
(XML). ``preview_import`` classifies incoming records against an
existing vault as new / duplicate / conflict without changing
anything; ``resolve_import`` applies a conflict policy.
"""

import csv
import io
import json
import xml.etree.ElementTree as ET


def _entry(service="", username="", password="", url="", notes="",
           totp_secret="", tags=None, favourite=False):
    return {
        "service": (service or "").strip(),
        "username": (username or "").strip(),
        "password": password or "",
        "url": (url or "").strip(),
        "notes": notes or "",
        "totp_secret": (totp_secret or "").strip(),
        "tags": list(tags or []),
        "favourite": bool(favourite),
    }


def _rows_from_csv(text):
    reader = csv.DictReader(io.StringIO(text))
    if reader.fieldnames is None:
        raise ValueError("CSV has no header row")
    headers = [(h or "").strip() for h in reader.fieldnames]
    rows = []
    for raw in reader:
        rows.append({(k or "").strip(): (v or "") for k, v in raw.items()})
    return headers, rows


# -- per-format row parsers ------------------------------------------------

def _chromium(rows):  # Chrome, Edge, Brave, Opera, Vivaldi, Arc, Google PM
    return [_entry(r.get("name"), r.get("username"), r.get("password"),
                   r.get("url"), r.get("note")) for r in rows]


def _firefox(rows):
    return [_entry(r.get("hostname") or r.get("url"), r.get("username"),
                   r.get("password"), r.get("url")) for r in rows]


def _safari(rows):
    return [_entry(r.get("Title"), r.get("Username"), r.get("Password"),
                   r.get("URL"), r.get("Notes"), r.get("OTPAuth")) for r in rows]


def _bitwarden_csv(rows):
    out = []
    for r in rows:
        if r.get("type") and r["type"] not in ("login", "1", ""):
            continue
        out.append(_entry(r.get("name"), r.get("login_username"),
                          r.get("login_password"), r.get("login_uri"),
                          r.get("notes"), r.get("login_totp"),
                          favourite=r.get("favorite") in ("1", "true", "True")))
    return out


def _onepassword(rows):
    return [_entry(r.get("Title"), r.get("Username"), r.get("Password"),
                   r.get("Url") or r.get("URL"), r.get("Notes"),
                   r.get("OTPAuth"),
                   tags=[t for t in (r.get("Tags") or "").split(";") if t],
                   favourite=r.get("Favorite") in ("true", "True", "1")) for r in rows]


def _lastpass(rows):
    return [_entry(r.get("name"), r.get("username"), r.get("password"),
                   r.get("url"), r.get("extra"),
                   favourite=r.get("fav") in ("1", "true")) for r in rows]


def _dashlane(rows):
    out = []
    for r in rows:
        username = r.get("username") or r.get("email") or r.get("username2") or ""
        out.append(_entry(r.get("title") or r.get("url"), username,
                          r.get("password"), r.get("url"), r.get("note"),
                          r.get("otpSecret") or r.get("2fa") or ""))
    return out


def _keepass_csv(rows):
    return [_entry(r.get("Title"), r.get("Username"), r.get("Password"),
                   r.get("URL"), r.get("Notes"),
                   tags=[t for t in (r.get("Group") or "").split("/") if t]) for r in rows]


def _nordpass(rows):
    out = []
    for r in rows:
        if r.get("password") or r.get("username"):
            out.append(_entry(r.get("name"), r.get("username"), r.get("password"),
                              r.get("url"), r.get("note")))
    return out


def _proton(rows):
    return [_entry(r.get("name"), r.get("username"), r.get("password"),
                   r.get("url"), r.get("note"), r.get("totp")) for r in rows]


_CSV_SIGNATURES = [
    # (format name, required header subset, parser)
    ("bitwarden-csv", {"login_username", "login_password"}, _bitwarden_csv),
    ("keepass-csv", {"Group", "Title", "Username", "Password"}, _keepass_csv),
    ("safari", {"Title", "URL", "Username", "Password"}, _safari),
    ("onepassword-csv", {"Title", "Username", "Password", "OTPAuth"}, _onepassword),
    ("lastpass", {"url", "username", "password", "extra", "name"}, _lastpass),
    ("firefox", {"url", "username", "password", "httpRealm"}, _firefox),
    ("proton", {"name", "url", "username", "password", "totp"}, _proton),
    ("dashlane", {"username", "password", "title"}, _dashlane),
    # Chromium-family exports (Chrome/Edge/Brave/Opera/Vivaldi/Arc and
    # Google Password Manager) share their exact header set with
    # NordPass; the parser is field-identical, so detection reports
    # "chromium" for that set and NordPass remains selectable
    # explicitly via --format nordpass.
    ("chromium", {"name", "url", "username", "password", "note"}, _chromium),
    ("chromium", {"name", "url", "username", "password"}, _chromium),
    ("nordpass", {"name", "url", "username", "password", "note"}, _nordpass),
]

FORMAT_ALIASES = {
    "chrome": "chromium", "edge": "chromium", "brave": "chromium",
    "opera": "chromium", "vivaldi": "chromium", "arc": "chromium",
    "chromium": "chromium", "google": "chromium",
    "firefox": "firefox", "safari": "safari", "icloud": "safari",
    "bitwarden": "bitwarden-csv", "bitwarden-csv": "bitwarden-csv",
    "bitwarden-json": "bitwarden-json",
    "1password": "onepassword-csv", "onepassword": "onepassword-csv",
    "onepassword-csv": "onepassword-csv",
    "lastpass": "lastpass", "dashlane": "dashlane",
    "keepass": "keepass-csv", "keepass-csv": "keepass-csv",
    "keepassxc": "keepass-csv", "keepass-xml": "keepass-xml",
    "nordpass": "nordpass", "proton": "proton", "protonpass": "proton",
    "generic": "generic",
}

_PARSERS = {name: parser for name, _, parser in _CSV_SIGNATURES}
_PARSERS["chromium"] = _chromium


def detect_format(text, filename=""):
    """Return a format name for CSV/JSON/XML text, or raise ValueError."""
    stripped = text.lstrip()
    if stripped.startswith("{"):
        data = json.loads(text)
        if isinstance(data, dict) and "items" in data:
            return "bitwarden-json"
        raise ValueError("unrecognised JSON export")
    if stripped.startswith("<"):
        return "keepass-xml"
    headers, _ = _rows_from_csv(text)
    header_set = set(headers)
    for name, required, _parser in _CSV_SIGNATURES:
        if required <= header_set:
            return name
    raise ValueError(f"unrecognised CSV headers: {headers}")


def parse_bitwarden_json(text):
    data = json.loads(text)
    out = []
    for item in data.get("items", []):
        login = item.get("login") or {}
        if item.get("type") not in (1, None) and not login:
            continue
        uris = login.get("uris") or []
        out.append(_entry(
            item.get("name"), login.get("username"), login.get("password"),
            uris[0].get("uri") if uris else "", item.get("notes"),
            login.get("totp"), favourite=bool(item.get("favorite")),
        ))
    return out


def parse_keepass_xml(text):
    root = ET.fromstring(text)
    out = []

    def walk(group, path):
        for entry_el in group.findall("Entry"):
            values = {}
            for s in entry_el.findall("String"):
                key_el, val_el = s.find("Key"), s.find("Value")
                if key_el is not None:
                    values[key_el.text or ""] = (val_el.text if val_el is not None else "") or ""
            if values.get("Title") or values.get("UserName"):
                out.append(_entry(
                    values.get("Title"), values.get("UserName"),
                    values.get("Password"), values.get("URL"),
                    values.get("Notes"), tags=[p for p in path if p],
                ))
        for sub in group.findall("Group"):
            name_el = sub.find("Name")
            walk(sub, path + [name_el.text if name_el is not None else ""])

    for group in root.iter("Group"):
        walk(group, [])
        break
    return out


def generic_map(rows, mapping):
    """Map arbitrary CSV rows: mapping is {entry_field: column_name}."""
    def pick(row, field):
        col = mapping.get(field)
        return row.get(col, "") if col else ""
    return [
        _entry(pick(r, "service"), pick(r, "username"), pick(r, "password"),
               pick(r, "url"), pick(r, "notes"), pick(r, "totp_secret"))
        for r in rows
    ]


def parse_import(text, format_name=None, mapping=None):
    """Parse export text into entry records. Returns (format, entries)."""
    fmt = FORMAT_ALIASES.get((format_name or "").lower()) if format_name else None
    if fmt is None:
        fmt = detect_format(text)
    if fmt == "bitwarden-json":
        return fmt, parse_bitwarden_json(text)
    if fmt == "keepass-xml":
        return fmt, parse_keepass_xml(text)
    _headers, rows = _rows_from_csv(text)
    if fmt == "generic":
        if not mapping:
            raise ValueError("generic import requires a column mapping")
        return fmt, generic_map(rows, mapping)
    entries = _PARSERS[fmt](rows)
    return fmt, [e for e in entries if e["service"] or e["username"]]


# -- preview / dedupe / conflicts ------------------------------------------

def _key(e):
    return (e["service"].lower(), e["username"].lower())


def preview_import(incoming, existing):
    by_key = {_key(e): e for e in existing}
    result = {"new": [], "duplicates": [], "conflicts": []}
    for e in incoming:
        current = by_key.get(_key(e))
        if current is None:
            result["new"].append(e)
        elif current["password"] == e["password"]:
            result["duplicates"].append(e)
        else:
            result["conflicts"].append(e)
    return result


def resolve_import(incoming, existing, on_conflict="skip"):
    """Return (merged_entries, stats). Policies: skip | overwrite | keep_both."""
    if on_conflict not in ("skip", "overwrite", "keep_both"):
        raise ValueError(f"unknown conflict policy: {on_conflict}")
    preview = preview_import(incoming, existing)
    merged = [dict(e) for e in existing]
    index = {_key(e): i for i, e in enumerate(merged)}
    stats = {"added": 0, "duplicates": len(preview["duplicates"]),
             "conflicts": len(preview["conflicts"]),
             "overwritten": 0, "kept_both": 0, "skipped_conflicts": 0}
    for e in preview["new"]:
        merged.append(dict(e))
        stats["added"] += 1
    for e in preview["conflicts"]:
        if on_conflict == "overwrite":
            merged[index[_key(e)]].update(e)
            stats["overwritten"] += 1
        elif on_conflict == "keep_both":
            merged.append(dict(e))
            stats["kept_both"] += 1
        else:
            stats["skipped_conflicts"] += 1
    return merged, stats
