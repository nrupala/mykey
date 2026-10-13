# Licensed under the Apache License, Version 2.0.
# Copyright (c) 2026 2351485 ALBERTA INC.

"""In-app help content guards (owner directive, 2026-10-13).

HELP.md / FAQ.md are the canonical help text: the GUI shows them
from the Help menu and the phone / web app mirrors them
byte-for-byte. These tests pin the promises the text must keep:
the sections users depend on exist, the parked Private vault is
never mentioned, and the in-app text carries no web links (the
apps work fully offline — help must too).
"""

import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(name):
    with open(os.path.join(ROOT, name), encoding="utf-8") as fh:
        return fh.read()


def test_help_and_faq_exist():
    assert _read("HELP.md").startswith("<!--")
    assert _read("FAQ.md").startswith("<!--")


def test_help_covers_the_core_topics():
    help_text = _read("HELP.md")
    for heading in (
        "Your master password",
        "Your recovery words",
        "Fingerprint unlock",
        "Sign-in codes",
        "Password dates and change reminders",
        "Sync through your own cloud",
        "Backup packages",
        "Pairing a cloud or export target",
        "Agents",
        "Colours and skins",
    ):
        assert heading in help_text, heading


def test_faq_answers_the_questions_that_matter():
    faq = _read("FAQ.md")
    for question in (
        "I forgot my master password",
        "I lost my phone",
        "Does MyKey work without internet",
        "Can the company read my passwords",
        "How do I bring my passwords from Chrome or Firefox",
    ):
        assert question in faq, question


def test_no_parked_or_unshipped_claims():
    for name in ("HELP.md", "FAQ.md"):
        text = _read(name)
        assert "Private vault" not in text
        assert "private vault" not in text


def test_help_text_is_offline_safe():
    for name in ("HELP.md", "FAQ.md"):
        text = _read(name)
        assert "http://" not in text
        assert "https://" not in text


def test_gui_wires_help_and_about():
    gui = _read("mykey_gui.py")
    assert '"HELP.md"' in gui
    assert '"FAQ.md"' in gui
    assert "101EEK" in gui  # the linked-attribution referral code
    assert "LICENSING.md" in gui  # licence summary points at the map
