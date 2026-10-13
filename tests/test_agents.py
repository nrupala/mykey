# Proprietary — Copyright (c) 2026 2351485 ALBERTA INC. All rights reserved.

import json
import os
import subprocess
import sys
import time

import pytest

from agents import (AgentAuthError, AgentGuard, AgentLockedError,
                    AgentScopeError, enroll_agent, list_agents,
                    open_agent_session, revoke_agent, set_agent_enabled,
                    set_agent_scopes, verify_audit)
from mykey import MyKey, make_entry

CORRECT = "Correct-Horse-2026!"
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


@pytest.fixture()
def vault_path(tmp_path):
    return str(tmp_path / "vault.mykey")


@pytest.fixture()
def enrolled(vault_path):
    """A vault with two entries and one agent: scopes list + get:github."""
    app = MyKey(CORRECT, vault_file=vault_path)
    app.add_entry(make_entry(service="github", username="octocat",
                             password="pw-github", tags=["dev"],
                             totp_secret="JBSWY3DPEHPK3PXP"))
    app.add_entry(make_entry(service="bank", username="joint",
                             password="pw-bank", tags=["finance"]))
    token = enroll_agent(app, "wright", ["list", "get:github"])
    return token


def test_enroll_access_within_scope(vault_path, enrolled):
    session = open_agent_session(vault_path, enrolled)
    meta = session.list_metadata()
    # bank is visible via 'list' but its password is not in metadata
    assert {m["service"] for m in meta} == {"github", "bank"}
    assert all("password" not in m for m in meta)
    entry = session.get("github")
    assert entry["password"] == "pw-github"
    assert "totp_secret" not in entry  # never leaves to agents


def test_out_of_scope_denied(vault_path, enrolled):
    session = open_agent_session(vault_path, enrolled)
    with pytest.raises(AgentScopeError):
        session.get("bank")


def test_tag_scope(vault_path):
    app = MyKey(CORRECT, vault_file=vault_path)
    app.add_entry(make_entry(service="github", password="pw-1", tags=["dev"]))
    app.add_entry(make_entry(service="bank", password="pw-2", tags=["finance"]))
    token = enroll_agent(app, "taggy", ["get:tag:dev"])
    session = open_agent_session(vault_path, token)
    assert session.get("github")["password"] == "pw-1"
    # v3: without 'list' the agent holds no metadata key, so an
    # out-of-scope entry is indistinguishable from a missing one
    # (KeyError) — the cryptographic form of the existence-oracle rule.
    with pytest.raises(KeyError):
        session.get("bank")
    # no 'list' scope: metadata shows only scope-visible entries
    assert [m["service"] for m in session.list_metadata()] == ["github"]


def test_write_scope_required_and_granted(vault_path):
    app = MyKey(CORRECT, vault_file=vault_path)
    app.save_password("github", "pw-1")
    reader = enroll_agent(app, "reader", ["get:github"])
    writer = enroll_agent(app, "writer", ["write"])
    with pytest.raises(AgentScopeError):
        open_agent_session(vault_path, reader).add_entry(
            {"service": "new", "password": "pw-new"})
    open_agent_session(vault_path, writer).add_entry(
        {"service": "new", "password": "pw-new"})
    assert MyKey(CORRECT, vault_file=vault_path).get_password("new") == "pw-new"


def test_revoked_token_denied(vault_path, enrolled):
    session = open_agent_session(vault_path, enrolled)
    assert session.get("github")["password"] == "pw-github"
    human = MyKey(CORRECT, vault_file=vault_path)
    human.unlock()
    revoke_agent(human, "wright")
    with pytest.raises(AgentAuthError):
        open_agent_session(vault_path, enrolled)


def test_disabled_token_denied(vault_path, enrolled):
    human = MyKey(CORRECT, vault_file=vault_path)
    human.unlock()
    set_agent_enabled(human, "wright", False)
    with pytest.raises(AgentAuthError):
        open_agent_session(vault_path, enrolled)
    set_agent_enabled(human, "wright", True)
    assert open_agent_session(vault_path, enrolled).agent_id == "wright"


def test_expired_token_denied(vault_path):
    app = MyKey(CORRECT, vault_file=vault_path)
    app.save_password("github", "pw-1")
    token = enroll_agent(app, "shortlived", ["list"], expires_days=1)
    # Force the expiry into the past inside the encrypted registry.
    app2 = MyKey(CORRECT, vault_file=vault_path)
    app2.unlock()
    app2._agents["shortlived"]["expires_at"] = int(time.time()) - 10
    app2._persist()
    with pytest.raises(AgentAuthError):
        open_agent_session(vault_path, token)


def test_wrong_token_progressive_backoff(vault_path, enrolled):
    """Phase 2B: the hard lockout is replaced by progressive backoff —
    failures open a doubling no-retry window, attempts inside it are
    refused WITHOUT extending it, and a human unlock clears it."""
    guard = AgentGuard(vault_path, base_seconds=0.3, cap_seconds=2.0)
    import base64
    bad = "mkag1.wright." + base64.urlsafe_b64encode(b"\x00" * 32).decode().rstrip("=")
    with pytest.raises(AgentAuthError):
        open_agent_session(vault_path, bad, guard=guard)
    # the legitimate agent is delayed, not locked out permanently
    with pytest.raises(AgentLockedError):
        open_agent_session(vault_path, enrolled, guard=guard)
    # a refused attempt inside the window does not extend it
    time.sleep(0.35)
    assert open_agent_session(vault_path, enrolled, guard=guard).agent_id == "wright"
    # second failure doubles the window
    with pytest.raises(AgentAuthError):
        open_agent_session(vault_path, bad, guard=guard)
    with pytest.raises(AgentLockedError):
        open_agent_session(vault_path, enrolled, guard=guard)
    # a successful human unlock clears the backoff instantly
    MyKey(CORRECT, vault_file=vault_path).unlock()
    assert open_agent_session(vault_path, enrolled, guard=guard).agent_id == "wright"


def test_audit_chain_verifies_and_detects_tamper(vault_path, enrolled):
    session = open_agent_session(vault_path, enrolled)
    session.list_metadata()
    with pytest.raises(AgentScopeError):
        session.get("bank")
    check = verify_audit(vault_path)
    assert check["ok"] and check["count"] >= 3  # auth allow, list, get deny
    path = vault_path + ".audit.jsonl"
    lines = open(path).read().splitlines()
    rec = json.loads(lines[-1])
    rec["result"] = "allow"  # tamper: rewrite a deny as an allow
    lines[-1] = json.dumps(rec, sort_keys=True)
    open(path, "w").write("\n".join(lines) + "\n")
    assert not verify_audit(vault_path)["ok"]


def test_audit_head_sealed_in_vault(vault_path, enrolled):
    open_agent_session(vault_path, enrolled)
    human = MyKey(CORRECT, vault_file=vault_path)
    human.unlock()
    check = verify_audit(vault_path, expected_head=human._audit_head)
    assert check["ok"]


def test_human_only_enrollment(vault_path, enrolled):
    """v3: an agent session holds NO vault-key-bearing object — the
    management surface does not exist on it, and the agent slot
    cannot be used as a wrapped-key unlock (it wraps a bundle key,
    not the vault key), so the engine fails closed."""
    import base64 as _b64

    from agents import parse_token
    from mykey import VaultCorrupt

    session = open_agent_session(vault_path, enrolled)
    assert not hasattr(session, "_vault")
    with pytest.raises(PermissionError):
        enroll_agent(session, "rogue", ["list"])
    with pytest.raises(PermissionError):
        revoke_agent(session, "wright")
    with pytest.raises(PermissionError):
        set_agent_enabled(session, "wright", False)
    agent_id, raw = parse_token(enrolled)
    slot = MyKey(CORRECT, vault_file=vault_path).get_slot(f"agent:{agent_id}")
    salt = _b64.b64decode(slot["salt"])
    params = {k: slot[k] for k in ("time_cost", "memory_cost", "parallelism")}
    wrapping = MyKey._derive_with_secret(raw, salt, "argon2id", params)
    probe = MyKey(CORRECT, vault_file=vault_path)
    with pytest.raises(VaultCorrupt):
        probe.unlock_via_wrapped_key(f"agent:{agent_id}", wrapping,
                                     principal="human")


def test_token_never_stored_and_registry_encrypted(vault_path, enrolled):
    raw = open(vault_path, "rb").read()
    secret = enrolled.split(".")[2]
    assert secret.encode() not in raw
    assert enrolled.encode() not in raw
    # The registry (hash, scopes, expiry) is inside the encrypted
    # payload. Only the slot id "agent:wright" is header metadata —
    # agent ids are identifiers, not secrets (same class as "master").
    assert b"token_hash" not in raw
    assert b"get:github" not in raw
    assert b"pw-github" not in raw


def test_registry_management_for_human(vault_path):
    app = MyKey(CORRECT, vault_file=vault_path)
    app.save_password("github", "pw-1")
    enroll_agent(app, "one", ["list"])
    enroll_agent(app, "two", ["get:github"], expires_days=30)
    with pytest.raises(ValueError):
        enroll_agent(app, "one", ["list"])  # duplicate
    with pytest.raises(ValueError):
        enroll_agent(app, "Bad Id!", ["list"])
    with pytest.raises(ValueError):
        enroll_agent(app, "three", ["fly-to-the-moon"])
    agents = {a["agent_id"]: a for a in list_agents(app)}
    assert set(agents) == {"one", "two"}
    assert agents["two"]["expires_at"] is not None
    assert all("token_hash" not in a for a in agents.values())
    set_agent_scopes(app, "one", ["list", "get:github"])
    assert list_agents(app)[0]["scopes"] == ["list", "get:github"]


def test_mcp_server_end_to_end(vault_path, enrolled):
    env = dict(os.environ)
    env["MYKEY_AGENT_KEY"] = enrolled
    env["MYKEY_VAULT"] = vault_path
    env["PYTHONPATH"] = ROOT
    msgs = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
         "params": {"name": "mykey_list", "arguments": {}}},
        {"jsonrpc": "2.0", "id": 4, "method": "tools/call",
         "params": {"name": "mykey_get", "arguments": {"service": "github"}}},
        {"jsonrpc": "2.0", "id": 5, "method": "tools/call",
         "params": {"name": "mykey_get", "arguments": {"service": "bank"}}},
    ]
    proc = subprocess.run(
        [sys.executable, os.path.join(ROOT, "mykey_mcp.py")],
        input="\n".join(json.dumps(m) for m in msgs) + "\n",
        capture_output=True, text=True, env=env, timeout=120)
    assert proc.returncode == 0, proc.stderr
    by_id = {}
    for line in proc.stdout.splitlines():
        msg = json.loads(line)
        by_id[msg["id"]] = msg
    assert by_id[1]["result"]["serverInfo"]["name"] == "mykey"
    tool_names = {t["name"] for t in by_id[2]["result"]["tools"]}
    assert tool_names == {"mykey_list", "mykey_get"}
    listed = json.loads(by_id[3]["result"]["content"][0]["text"])
    assert {m["service"] for m in listed} == {"github", "bank"}
    got = json.loads(by_id[4]["result"]["content"][0]["text"])
    assert got["password"] == "pw-github"
    denied = by_id[5]["result"]
    assert denied["isError"] is True
    assert "pw-bank" not in denied["content"][0]["text"]


def test_mcp_revocation_takes_effect_mid_process(vault_path, enrolled):
    """A long-lived MCP process must honour revocation on the next call."""
    env = dict(os.environ)
    env["MYKEY_AGENT_KEY"] = enrolled
    env["MYKEY_VAULT"] = vault_path
    env["PYTHONPATH"] = ROOT
    proc = subprocess.Popen(
        [sys.executable, os.path.join(ROOT, "mykey_mcp.py")],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        text=True, env=env)
    try:
        def call(req_id, service):
            proc.stdin.write(json.dumps({
                "jsonrpc": "2.0", "id": req_id, "method": "tools/call",
                "params": {"name": "mykey_get",
                           "arguments": {"service": service}}}) + "\n")
            proc.stdin.flush()
            return json.loads(proc.stdout.readline())

        ok = call(1, "github")
        assert json.loads(ok["result"]["content"][0]["text"])["password"] == "pw-github"
        human = MyKey(CORRECT, vault_file=vault_path)
        human.unlock()
        revoke_agent(human, "wright")
        denied = call(2, "github")
        assert denied["result"]["isError"] is True
        assert "pw-github" not in denied["result"]["content"][0]["text"]
    finally:
        proc.stdin.close()
        proc.wait(timeout=30)


def test_cli_agent_flow(vault_path, tmp_path):
    env = dict(os.environ)
    env["PYTHONPATH"] = ROOT

    def run_cli(args, master=None, extra_env=None):
        e = dict(env)
        if extra_env:
            e.update(extra_env)
        return subprocess.run(
            [sys.executable, os.path.join(ROOT, "mykey_cli.py")] + args,
            input=(master + "\n") if master else "",
            capture_output=True, text=True, env=e, timeout=120,
            cwd=str(tmp_path))

    # human creates a vault entry
    r = run_cli(["add", "--service", "github", "--vault", vault_path],
                master=CORRECT + "\n" + "pw-github")
    # add prompts master, then the entry password via getpass (stdin)
    assert r.returncode == 0, r.stderr
    # human enrolls an agent
    r = run_cli(["agent-enroll", "--agent-id", "wright",
                 "--scopes", "list,get:github", "--vault", vault_path],
                master=CORRECT)
    assert r.returncode == 0, r.stderr
    token = [ln for ln in r.stdout.splitlines()
             if ln.startswith("mkag1.")][0].strip()
    # agent lists + gets without any master password
    r = run_cli(["agent-list", "--vault", vault_path],
                extra_env={"MYKEY_AGENT_KEY": token})
    assert r.returncode == 0 and "github" in r.stdout, r.stderr
    r = run_cli(["agent-get", "--service", "github", "--vault", vault_path],
                extra_env={"MYKEY_AGENT_KEY": token})
    assert r.returncode == 0 and "pw-github" in r.stdout, r.stderr
    # missing token is a clean error, not a master prompt
    r = run_cli(["agent-get", "--service", "github", "--vault", vault_path])
    assert r.returncode == 2 and "MYKEY_AGENT_KEY" in r.stderr
