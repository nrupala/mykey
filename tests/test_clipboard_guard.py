"""Clipboard self-clear rule (owner directive, 2026-10-13).

A copied secret stays on the clipboard 60 seconds by default; the
user may set 60–300 seconds; anything outside is clamped at the
single validation point. The guard clears only what it put there,
lock/close clears immediately, and a re-copy restarts the timer.

The desktop GUI's only copy action (copy_pw, passwords) routes
through this guard; values copied here stand in for any secret —
the mechanism is identical for a TOTP code.
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from clipboard_guard import (
    CLIPBOARD_CLEAR_DEFAULT_SECONDS,
    CLIPBOARD_CLEAR_MAX_SECONDS,
    CLIPBOARD_CLEAR_MIN_SECONDS,
    ClipboardGuard,
    clamp_clipboard_clear_seconds,
    load_clipboard_clear_seconds,
    save_clipboard_clear_seconds,
)


class FakeClipboard:
    def __init__(self):
        self.content = ""

    def copy(self, value):
        self.content = value

    def paste(self):
        return self.content


class FakeTimer:
    def __init__(self, delay, callback):
        self.delay = delay
        self.callback = callback
        self.cancelled = False
        self.started = False

    def start(self):
        self.started = True

    def cancel(self):
        self.cancelled = True

    def fire(self):
        if self.started and not self.cancelled:
            self.callback()


def make_guard(clear_seconds=None):
    clip = FakeClipboard()
    timers = []

    def factory(delay, callback):
        timer = FakeTimer(delay, callback)
        timers.append(timer)
        return timer

    kwargs = {} if clear_seconds is None else {"clear_seconds": clear_seconds}
    guard = ClipboardGuard(copy_fn=clip.copy, paste_fn=clip.paste,
                           timer_factory=factory, **kwargs)
    return guard, clip, timers


# -- the constant and the single validation point --------------------

def test_default_is_60():
    assert CLIPBOARD_CLEAR_DEFAULT_SECONDS == 60
    guard, _, _ = make_guard()
    assert guard.clear_seconds == 60


def test_bounds_are_60_and_300():
    assert CLIPBOARD_CLEAR_MIN_SECONDS == 60
    assert CLIPBOARD_CLEAR_MAX_SECONDS == 300


def test_clamp_refuses_out_of_bounds_values():
    assert clamp_clipboard_clear_seconds(59) == 60
    assert clamp_clipboard_clear_seconds(301) == 300
    assert clamp_clipboard_clear_seconds(0) == 60
    assert clamp_clipboard_clear_seconds(10_000) == 300


def test_clamp_honours_in_bounds_values():
    assert clamp_clipboard_clear_seconds(60) == 60
    assert clamp_clipboard_clear_seconds(120) == 120
    assert clamp_clipboard_clear_seconds(300) == 300


def test_clamp_falls_back_to_default_on_garbage():
    assert clamp_clipboard_clear_seconds(None) == 60
    assert clamp_clipboard_clear_seconds("abc") == 60
    assert clamp_clipboard_clear_seconds(float("nan")) == 60
    assert clamp_clipboard_clear_seconds(float("inf")) == 60
    assert clamp_clipboard_clear_seconds(True) == 60


# -- timer behaviour --------------------------------------------------

def test_timer_uses_configured_value():
    guard, clip, timers = make_guard(clear_seconds=120)
    guard.copy("s3cret")
    assert timers[-1].delay == 120
    assert clip.content == "s3cret"  # not cleared before the delay

    guard60, _, timers60 = make_guard()
    guard60.copy("s3cret")
    assert timers60[-1].delay == 60


def test_timer_clears_what_we_put_there():
    guard, clip, timers = make_guard()
    guard.copy("s3cret")
    timers[-1].fire()
    assert clip.content == ""


def test_timer_leaves_content_the_user_copied_afterwards():
    guard, clip, timers = make_guard()
    guard.copy("s3cret")
    clip.content = "something the user copied elsewhere"
    timers[-1].fire()
    assert clip.content == "something the user copied elsewhere"


def test_lock_clear_now_clears_immediately():
    guard, clip, timers = make_guard(clear_seconds=300)
    guard.copy("s3cret")
    guard.clear_now()  # no timer fire needed — this is the lock path
    assert clip.content == ""
    assert timers[-1].cancelled  # and the pending timer is dead


def test_clear_now_still_respects_the_match_guard():
    guard, clip, _ = make_guard()
    guard.copy("s3cret")
    clip.content = "not ours anymore"
    guard.clear_now()
    assert clip.content == "not ours anymore"


def test_recopy_restarts_the_timer():
    guard, clip, timers = make_guard()
    guard.copy("first")
    guard.copy("second")
    assert timers[0].cancelled
    timers[0].fire()  # stale timer must not wipe the newer copy
    assert clip.content == "second"
    timers[1].fire()
    assert clip.content == ""


def test_totp_code_copy_follows_the_same_rule():
    guard, clip, timers = make_guard()
    guard.copy("287082")  # a sign-in code, copied exactly like a password
    timers[-1].fire()
    assert clip.content == ""


def test_set_clear_seconds_applies_to_next_copy_clamped():
    guard, _, timers = make_guard()
    assert guard.set_clear_seconds(45) == 60  # clamped, not accepted
    guard.copy("s3cret")
    assert timers[-1].delay == 60
    assert guard.set_clear_seconds(240) == 240
    guard.copy("s3cret")
    assert timers[-1].delay == 240


# -- persistence ------------------------------------------------------

def test_preferences_round_trip(tmp_path):
    path = str(tmp_path / "preferences.json")
    assert load_clipboard_clear_seconds(path) == 60  # missing file
    assert save_clipboard_clear_seconds(120, path) == 120
    assert load_clipboard_clear_seconds(path) == 120
    with open(path, encoding="utf-8") as f:
        assert json.load(f)["clipboard_clear_seconds"] == 120


def test_preferences_clamp_on_load_and_save(tmp_path):
    path = str(tmp_path / "preferences.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"clipboard_clear_seconds": 30}, f)  # legacy value
    assert load_clipboard_clear_seconds(path) == 60
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"clipboard_clear_seconds": 999}, f)
    assert load_clipboard_clear_seconds(path) == 300
    assert save_clipboard_clear_seconds(301, path) == 300
    assert save_clipboard_clear_seconds(59, path) == 60
