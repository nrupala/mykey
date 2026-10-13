# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Copyright (c) 2026 2351485 ALBERTA INC.

"""Clipboard self-clear for copied secrets (Apache 2.0 interface layer).

The rule (owner directive, 2026-10-13): a password copied from the
app stays on the clipboard for a short, bounded time — 1 minute by
default — and then clears itself, restricting leakage. The user may
choose a longer delay, but only inside hard bounds: never less than
60 seconds, never more than 300. Values outside the bounds are
clamped at the single validation point in this module
(``clamp_clipboard_clear_seconds``), never silently accepted as-is.

Behaviour:
* copying a secret starts the timer; copying again restarts it;
* when the timer fires, the clipboard is cleared ONLY if its current
  content is still exactly what the app put there — anything the
  user copied afterwards, from anywhere, is left untouched;
* locking/closing clears a pending copied secret immediately
  (same content-still-matches guard);
* the delay persists as a non-secret preference in
  ``~/.mykey/preferences.json`` and applies to the next copy.

The desktop GUI is the only desktop surface with a copy action
(``copy_pw``); the CLI and MCP surfaces print for the human and
never touch the clipboard, so there is nothing to guard there.
"""

import json
import math
import os
import threading

import pyperclip

# Leakage rule (owner, 2026-10-13): copied secrets clear after
# 1 minute by default; the user may pick 60–300 seconds, no more,
# no less. These constants are the single source for the bounds.
CLIPBOARD_CLEAR_DEFAULT_SECONDS = 60
CLIPBOARD_CLEAR_MIN_SECONDS = 60
CLIPBOARD_CLEAR_MAX_SECONDS = 300

PREFERENCES_ENV = "MYKEY_PREFERENCES_FILE"
_PREFERENCE_KEY = "clipboard_clear_seconds"


def clamp_clipboard_clear_seconds(value) -> int:
    """The single validation point for the clear delay.

    Anything unusable (None, non-numeric, NaN/inf) falls back to the
    default; usable numbers are rounded and clamped into
    [MIN, MAX] — 59 becomes 60, 301 becomes 300.
    """
    try:
        if isinstance(value, bool) or value is None:
            raise ValueError("not a number")
        seconds = float(value)
    except (TypeError, ValueError):
        return CLIPBOARD_CLEAR_DEFAULT_SECONDS
    if not math.isfinite(seconds):
        return CLIPBOARD_CLEAR_DEFAULT_SECONDS
    return max(CLIPBOARD_CLEAR_MIN_SECONDS,
               min(CLIPBOARD_CLEAR_MAX_SECONDS, round(seconds)))


# -- preference persistence (non-secret; ~/.mykey/preferences.json) --

def default_preferences_path() -> str:
    override = os.environ.get(PREFERENCES_ENV)
    if override:
        return override
    return os.path.join(os.path.expanduser("~"), ".mykey", "preferences.json")


def load_preferences(path=None) -> dict:
    try:
        with open(path or default_preferences_path(), encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def load_clipboard_clear_seconds(path=None) -> int:
    return clamp_clipboard_clear_seconds(
        load_preferences(path).get(_PREFERENCE_KEY))


def save_clipboard_clear_seconds(seconds, path=None) -> int:
    """Persist the (clamped) delay; returns the value stored."""
    target = path or default_preferences_path()
    prefs = load_preferences(target)
    prefs[_PREFERENCE_KEY] = clamp_clipboard_clear_seconds(seconds)
    directory = os.path.dirname(os.path.abspath(target))
    os.makedirs(directory, exist_ok=True)
    tmp = target + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(prefs, f)
        f.flush()
        os.fsync(f.fileno())
    os.chmod(tmp, 0o600)
    os.replace(tmp, target)
    os.chmod(target, 0o600)
    return prefs[_PREFERENCE_KEY]


# -- the guard -------------------------------------------------------

def _threading_timer(delay, callback):
    timer = threading.Timer(delay, callback)
    timer.daemon = True
    return timer


class ClipboardGuard:
    """Owns the one pending copied secret and its clear timer.

    Clipboard access and the timer are injectable so the behaviour
    is testable without a real system clipboard.
    """

    def __init__(self, copy_fn=None, paste_fn=None, timer_factory=None,
                 clear_seconds=None):
        self._copy = copy_fn or pyperclip.copy
        self._paste = paste_fn or pyperclip.paste
        self._timer_factory = timer_factory or _threading_timer
        self._clear_seconds = clamp_clipboard_clear_seconds(
            CLIPBOARD_CLEAR_DEFAULT_SECONDS if clear_seconds is None
            else clear_seconds)
        self._lock = threading.Lock()
        self._pending = None      # the exact value we placed, or None
        self._timer = None
        self._generation = 0      # invalidates older timers on re-copy

    @property
    def clear_seconds(self) -> int:
        return self._clear_seconds

    def set_clear_seconds(self, seconds) -> int:
        """Set the delay for the NEXT copy (clamped, as always)."""
        self._clear_seconds = clamp_clipboard_clear_seconds(seconds)
        return self._clear_seconds

    def copy(self, value: str) -> None:
        """Place a secret on the clipboard and arm its clear timer."""
        self._copy(value)
        with self._lock:
            self._generation += 1
            generation = self._generation
            self._pending = value
            self._cancel_timer_locked()
            self._timer = self._timer_factory(
                self._clear_seconds, lambda: self._expire(generation))
            self._timer.start()

    def clear_now(self) -> None:
        """Lock/close path: clear the pending secret immediately.

        Still honours the content-still-matches guard — if the user
        has since copied something else, that content is theirs.
        """
        with self._lock:
            self._generation += 1
            value = self._pending
            self._pending = None
            self._cancel_timer_locked()
        if value is not None:
            self._clear_if_current(value)

    def _expire(self, generation: int) -> None:
        with self._lock:
            if generation != self._generation or self._pending is None:
                return
            value = self._pending
            self._pending = None
            self._timer = None
        self._clear_if_current(value)

    def _clear_if_current(self, value: str) -> None:
        try:
            current = self._paste()
        except Exception:
            return  # clipboard unreadable — never claim a clear
        if current == value:
            try:
                self._copy("")
            except Exception:
                pass

    def _cancel_timer_locked(self) -> None:
        if self._timer is not None:
            try:
                self._timer.cancel()
            except Exception:
                pass
            self._timer = None
