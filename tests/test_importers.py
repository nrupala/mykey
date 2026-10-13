# Proprietary — Copyright (c) 2026 2351485 ALBERTA INC. All rights reserved.

import json

import pytest

from importers import parse_import, preview_import, resolve_import

CHROMIUM = """name,url,username,password,note
GitHub,https://github.com,octocat,pw-gh,work account
Bank,https://bank.example,alice,pw-bank,
"""

FIREFOX = """url,username,password,httpRealm,formActionOrigin,usernameField,passwordField
https://github.com,octocat,pw-gh,https://github.com,https://github.com,login,password
"""

SAFARI = """Title,URL,Username,Password,Notes,OTPAuth
GitHub,https://github.com,octocat,pw-gh,work,otpauth://totp/GitHub:octocat?secret=JBSWY3DPEHPK3PXP
"""

BITWARDEN_CSV = """folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp
,1,login,GitHub,work,,0,https://github.com,octocat,pw-gh,JBSWY3DPEHPK3PXP
"""

BITWARDEN_JSON = json.dumps({
    "folders": [],
    "items": [{
        "id": "1", "type": 1, "name": "GitHub", "notes": "work", "favorite": True,
        "login": {"username": "octocat", "password": "pw-gh",
                  "totp": "JBSWY3DPEHPK3PXP",
                  "uris": [{"uri": "https://github.com"}]},
    }],
})

ONEPASSWORD = """Title,Url,Username,Password,OTPAuth,Notes,Favorite,Archived,Tags
GitHub,https://github.com,octocat,pw-gh,JBSWY3DPEHPK3PXP,work,true,,dev;work
"""

LASTPASS = """url,username,password,extra,name,grouping,fav
https://github.com,octocat,pw-gh,work note,GitHub,,1
"""

DASHLANE = """username,email,2fa,url,title,password,note
octocat,,,https://github.com,GitHub,pw-gh,work
"""

KEEPASS_CSV = """Group,Title,Username,Password,URL,Notes
Web/GitHub,GitHub,octocat,pw-gh,https://github.com,work
"""

KEEPASS_XML = """<KeePassFile><Root><Group><Name>Root</Name>
<Entry><String><Key>Title</Key><Value>GitHub</Value></String>
<String><Key>UserName</Key><Value>octocat</Value></String>
<String><Key>Password</Key><Value>pw-gh</Value></String>
<String><Key>URL</Key><Value>https://github.com</Value></String>
<String><Key>Notes</Key><Value>work</Value></String></Entry>
</Group></Root></KeePassFile>
"""

NORDPASS = """name,url,username,password,note,folder
GitHub,https://github.com,octocat,pw-gh,work,
"""

PROTON = """name,url,username,password,note,totp
GitHub,https://github.com,octocat,pw-gh,work,JBSWY3DPEHPK3PXP
"""

GENERIC = """Site,User,Pass
GitHub,octocat,pw-gh
"""


@pytest.mark.parametrize("text,fmt", [
    (CHROMIUM, "chromium"), (FIREFOX, "firefox"), (SAFARI, "safari"),
    (BITWARDEN_CSV, "bitwarden-csv"), (ONEPASSWORD, "onepassword-csv"),
    (LASTPASS, "lastpass"), (DASHLANE, "dashlane"),
    (KEEPASS_CSV, "keepass-csv"), (PROTON, "proton"),
])
def test_csv_formats_parse(text, fmt):
    detected, entries = parse_import(text)
    assert detected == fmt
    assert "github" in entries[0]["service"].lower()  # Firefox keys entries by URL
    assert entries[0]["username"] == "octocat"
    assert entries[0]["password"] == "pw-gh"


def test_chromium_family_multiple_rows():
    _fmt, entries = parse_import(CHROMIUM)
    assert len(entries) == 2
    assert entries[1]["service"] == "Bank"


def test_bitwarden_json():
    fmt, entries = parse_import(BITWARDEN_JSON)
    assert fmt == "bitwarden-json"
    assert entries[0]["totp_secret"] == "JBSWY3DPEHPK3PXP"
    assert entries[0]["favourite"] is True


def test_keepass_xml():
    fmt, entries = parse_import(KEEPASS_XML)
    assert fmt == "keepass-xml"
    assert entries[0]["password"] == "pw-gh"


def test_nordpass_explicit_format():
    fmt, entries = parse_import(NORDPASS, "nordpass")
    assert fmt == "nordpass"
    assert entries[0]["password"] == "pw-gh"


def test_safari_totp_captured():
    _fmt, entries = parse_import(SAFARI)
    assert "JBSWY3DPEHPK3PXP" in entries[0]["totp_secret"]


def test_generic_mapper():
    mapping = {"service": "Site", "username": "User", "password": "Pass"}
    fmt, entries = parse_import(GENERIC, "generic", mapping=mapping)
    assert fmt == "generic"
    assert entries[0]["password"] == "pw-gh"


def test_unknown_format_rejected():
    with pytest.raises(Exception):
        parse_import("a,b,c\n1,2,3\n")


def _existing():
    return [
        {"service": "GitHub", "username": "octocat", "password": "pw-gh",
         "url": "", "notes": "", "totp_secret": "", "tags": [], "favourite": False},
        {"service": "Bank", "username": "alice", "password": "old-pw",
         "url": "", "notes": "", "totp_secret": "", "tags": [], "favourite": False},
    ]


def _incoming():
    return [
        {"service": "GitHub", "username": "octocat", "password": "pw-gh",
         "url": "", "notes": "", "totp_secret": "", "tags": [], "favourite": False},
        {"service": "Bank", "username": "alice", "password": "new-pw",
         "url": "", "notes": "", "totp_secret": "", "tags": [], "favourite": False},
        {"service": "New Site", "username": "bob", "password": "pw-new",
         "url": "", "notes": "", "totp_secret": "", "tags": [], "favourite": False},
    ]


def test_preview_classifies():
    preview = preview_import(_incoming(), _existing())
    assert len(preview["new"]) == 1
    assert len(preview["duplicates"]) == 1
    assert len(preview["conflicts"]) == 1


@pytest.mark.parametrize("policy,expected_bank_pw,expected_count", [
    ("skip", "old-pw", 3),
    ("overwrite", "new-pw", 3),
    ("keep_both", "old-pw", 4),
])
def test_resolve_policies(policy, expected_bank_pw, expected_count):
    merged, stats = resolve_import(_incoming(), _existing(), on_conflict=policy)
    assert len(merged) == expected_count
    bank = next(e for e in merged if e["service"] == "Bank")
    assert bank["password"] == expected_bank_pw
    assert stats["added"] == 1 and stats["duplicates"] == 1
