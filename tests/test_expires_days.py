# Proprietary — Copyright (c) 2026 2351485 ALBERTA INC. All rights reserved.

"""Issue #12: --expires-days 0 must never silently mint a
never-expiring grant.

0 (and any negative) is REFUSED at both the API and CLI level with
a plain error; omitting the value is the only way to create a
non-expiring agent or pairing, and the enroll output echoes the
effective expiry so the choice is visible at the moment it is
made. The stored expiry must match what the output claimed.
"""

import os
import subprocess
import sys
import time

import pytest

import pairings
from agents import enroll_agent, list_agents
from mykey import MyKey
from pairings import PairingError, PairingTargetIdentity

CORRECT = "Correct-Horse-2026!"
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


@pytest.fixture()
def vault_path(tmp_path):
    return str(tmp_path / "vault.mykey")


def _vault(vault_path):
    return MyKey(CORRECT, vault_file=vault_path)


# ---------------------------------------------------------------------------
# agent enrollment (API level)
# ---------------------------------------------------------------------------

def test_agent_zero_days_refused(vault_path):
    app = _vault(vault_path)
    with pytest.raises(ValueError, match="at least 1 day"):
        enroll_agent(app, "mayfly", ["list"], expires_days=0)
    assert list_agents(app) == []  # nothing was enrolled


def test_agent_negative_days_refused(vault_path):
    app = _vault(vault_path)
    with pytest.raises(ValueError, match="at least 1 day"):
        enroll_agent(app, "mayfly", ["list"], expires_days=-1)
    assert list_agents(app) == []


def test_agent_fractional_days_refused(vault_path):
    app = _vault(vault_path)
    with pytest.raises(ValueError, match="whole number"):
        enroll_agent(app, "mayfly", ["list"], expires_days=1.5)
    assert list_agents(app) == []


def test_agent_one_day_sets_matching_expiry(vault_path):
    app = _vault(vault_path)
    before = int(time.time())
    enroll_agent(app, "mayfly", ["list"], expires_days=1)
    after = int(time.time())
    (rec,) = list_agents(app)
    assert before + 86400 <= rec["expires_at"] <= after + 86400


def test_agent_omitted_never_expires(vault_path):
    app = _vault(vault_path)
    enroll_agent(app, "mayfly", ["list"])
    (rec,) = list_agents(app)
    assert rec["expires_at"] is None


# ---------------------------------------------------------------------------
# pairing enrollment (API level) — the sibling parse site
# ---------------------------------------------------------------------------

def _target():
    return PairingTargetIdentity.generate("export", "T")


def test_pairing_zero_days_refused(vault_path):
    app = _vault(vault_path)
    with pytest.raises(PairingError, match="at least 1 day"):
        pairings.enroll_pairing(app, _target().payload(), ["export"],
                                expires_days=0)
    assert pairings.list_pairings(app) == []


def test_pairing_negative_days_refused(vault_path):
    app = _vault(vault_path)
    with pytest.raises(PairingError, match="at least 1 day"):
        pairings.enroll_pairing(app, _target().payload(), ["export"],
                                expires_days=-2)
    assert pairings.list_pairings(app) == []


def test_pairing_two_days_sets_matching_expiry(vault_path):
    app = _vault(vault_path)
    before = int(time.time())
    rec = pairings.enroll_pairing(app, _target().payload(), ["export"],
                                  expires_days=2)
    after = int(time.time())
    assert before + 2 * 86400 <= rec["expires_at"] <= after + 2 * 86400


def test_pairing_omitted_never_expires(vault_path):
    app = _vault(vault_path)
    rec = pairings.enroll_pairing(app, _target().payload(), ["export"])
    assert rec["expires_at"] is None


# ---------------------------------------------------------------------------
# CLI level: refusal is plain, and the effective grant is echoed
# ---------------------------------------------------------------------------

def _run_cli(tmp_path, args, master=None):
    env = dict(os.environ)
    env["PYTHONPATH"] = ROOT
    return subprocess.run(
        [sys.executable, os.path.join(ROOT, "mykey_cli.py")] + args,
        input=(master + "\n") if master else "",
        capture_output=True, text=True, env=env, timeout=120,
        cwd=str(tmp_path))


def _make_vault(tmp_path, vault_path):
    r = _run_cli(tmp_path, ["add", "--service", "github",
                            "--vault", vault_path],
                 master=CORRECT + "\n" + "pw-github")
    assert r.returncode == 0, r.stderr


def test_cli_zero_days_refused_plainly(tmp_path, vault_path):
    _make_vault(tmp_path, vault_path)
    r = _run_cli(tmp_path, ["agent-enroll", "--agent-id", "mayfly",
                            "--scopes", "list", "--expires-days", "0",
                            "--vault", vault_path], master=CORRECT)
    assert r.returncode != 0
    assert "at least 1 day" in r.stderr
    assert "Traceback" not in r.stderr
    # and the refused enrollment really did not happen
    r = _run_cli(tmp_path, ["agents", "--vault", vault_path],
                 master=CORRECT)
    assert r.returncode == 0, r.stderr
    assert "mayfly" not in r.stdout


def test_cli_negative_days_refused_plainly(tmp_path, vault_path):
    _make_vault(tmp_path, vault_path)
    r = _run_cli(tmp_path, ["agent-enroll", "--agent-id", "mayfly",
                            "--scopes", "list", "--expires-days", "-1",
                            "--vault", vault_path], master=CORRECT)
    assert r.returncode != 0
    assert "at least 1 day" in r.stderr


def test_cli_enroll_echoes_expiry_date(tmp_path, vault_path):
    _make_vault(tmp_path, vault_path)
    before = int(time.time())
    r = _run_cli(tmp_path, ["agent-enroll", "--agent-id", "mayfly",
                            "--scopes", "list,get:github",
                            "--expires-days", "1",
                            "--vault", vault_path], master=CORRECT)
    after = int(time.time())
    assert r.returncode == 0, r.stderr
    assert "Scopes: list, get:github" in r.stdout
    dates = {time.strftime("%Y-%m-%d", time.localtime(t + 86400))
             for t in (before, after)}
    expires_lines = [ln for ln in r.stdout.splitlines()
                     if ln.strip().startswith("Expires:")]
    assert expires_lines and any(d in expires_lines[0] for d in dates)
    assert any(ln.startswith("mkag1.") for ln in r.stdout.splitlines())
    # the stored grant matches what the output claimed
    r = _run_cli(tmp_path, ["agents", "--vault", vault_path],
                 master=CORRECT)
    (line,) = [ln for ln in r.stdout.splitlines() if "mayfly" in ln]
    assert "expires=never" not in line
    shown = int(line.split("expires=")[1].split()[0])
    assert before + 86400 <= shown <= after + 86400


def test_cli_enroll_echoes_never(tmp_path, vault_path):
    _make_vault(tmp_path, vault_path)
    r = _run_cli(tmp_path, ["agent-enroll", "--agent-id", "mayfly",
                            "--scopes", "list",
                            "--vault", vault_path], master=CORRECT)
    assert r.returncode == 0, r.stderr
    assert "Expires: never" in r.stdout
