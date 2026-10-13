# Proprietary — Copyright (c) 2026 2351485 ALBERTA INC. All rights reserved.
"""Phase 2B killer tests: Vault v3 key partitioning, audit anchor,
progressive backoff visibility, migration and downgrade defences.

The partitioning tests are written as ATTACKS: they take everything
an agent token legitimately yields (the bundle), plus raw file
access, and try to decrypt what is out of scope with raw crypto.
Every such attempt must fail with an AEAD error — not with a polite
in-process refusal.
"""

import base64
import json
import os
import time

import pytest
from argon2 import low_level
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import agents
from agents import (AgentAuthError, AgentGuard, AgentLockedError,
                    AgentScopeError, enroll_agent, open_agent_session,
                    read_audit, revoke_agent, set_agent_enabled,
                    set_agent_scopes)
from mykey import (AuditAnchorError, MyKey, VaultCorrupt, _aad, _b64d,
                   _dec, make_entry)

CORRECT = "Correct-Horse-2026!"


@pytest.fixture()
def vault_path(tmp_path):
    return str(tmp_path / "vault.mykey")


@pytest.fixture()
def stocked(vault_path):
    app = MyKey(CORRECT, vault_file=vault_path)
    app.add_entry(make_entry(service="github", username="octocat",
                             password="pw-github", notes="n-gh",
                             totp_secret="JBSWY3DPEHPK3PXP", tags=["dev"]))
    app.add_entry(make_entry(service="bank", username="joint",
                             password="pw-bank", notes="n-bank",
                             tags=["finance"]))
    return app


def _extract_bundle(vault_path, token):
    """Everything a token legitimately yields: (bundle_key, bundle)."""
    agent_id, raw = agents.parse_token(token)
    data = json.load(open(vault_path))
    slot = next(s for s in data["slots"] if s["id"] == f"agent:{agent_id}")
    salt = base64.b64decode(slot["salt"])
    params = {k: slot[k] for k in ("time_cost", "memory_cost", "parallelism")}
    wrapping = MyKey._derive_with_secret(raw, salt, "argon2id", params)
    bk = MyKey._unwrap_slot(slot, wrapping)
    assert bk is not None
    bundle = json.loads(_dec(bk, data["bundles"][agent_id], _aad("bundle", agent_id)))
    return bk, bundle, data


def _entry_obj(data, service, kmeta=None):
    """Locate a raw entry object by service (via metadata key if given,
    else by trying every object — the attacker does not know ids)."""
    for obj in data["entries"]:
        if obj.get("pending") is not None:
            continue
        if kmeta is not None:
            meta = json.loads(_dec(kmeta, obj["meta"], _aad("meta", obj["id"])))
            if meta["service"] == service:
                return obj
    return None


# ---------------------------------------------------------------------------
# (a) cryptographic scope enforcement — raw attacks
# ---------------------------------------------------------------------------

def test_agent_keys_cannot_decrypt_out_of_scope(vault_path, stocked):
    token = enroll_agent(stocked, "narrow", ["get:github"])
    bk, bundle, data = _extract_bundle(vault_path, token)

    # the bundle contains exactly the in-scope key material
    assert bundle["kmeta"] is None  # no 'list' scope -> no metadata key
    assert set(bundle["services"]) == {"github"}  # no out-of-scope index
    github_id = bundle["services"]["github"]
    assert set(bundle["targets"]) == {github_id}

    # sanity: the in-scope key really does decrypt github's secret
    gh = next(o for o in data["entries"] if o["id"] == github_id)
    secret = json.loads(_dec(_b64d(bundle["targets"][github_id]["dek_pw"]),
                             gh["secret"], _aad("secret", github_id)))
    assert secret["password"] == "pw-github"

    bank = next(o for o in data["entries"] if o["id"] != github_id)
    # attack 1: bundle key against the core and every ciphertext
    for blob, kind in ((data["core"], "core"), (bank["secret"], "secret"),
                       (bank["meta"], "meta"), (gh["totp"], "totp")):
        with pytest.raises(InvalidTag):
            AESGCM(bk).decrypt(_b64d(blob["nonce"]), _b64d(blob["ciphertext"]),
                               _aad(kind, bank["id"]) if kind != "core"
                               else _aad("core", data["vault_id"]))
    # attack 2: the in-scope DEK against the out-of-scope entry
    with pytest.raises(InvalidTag):
        _dec(_b64d(bundle["targets"][github_id]["dek_pw"]),
             bank["secret"], _aad("secret", bank["id"]))
    # attack 3: github's DEK against github's own TOTP ciphertext —
    # TOTP keys are never in any bundle, not even for in-scope entries
    with pytest.raises(InvalidTag):
        _dec(_b64d(bundle["targets"][github_id]["dek_pw"]),
             gh["totp"], _aad("totp", github_id))


def test_list_bundle_metadata_key_opens_no_secrets(vault_path, stocked):
    token = enroll_agent(stocked, "lister", ["list"])
    _bk, bundle, data = _extract_bundle(vault_path, token)
    kmeta = _b64d(bundle["kmeta"])
    assert bundle["targets"] == {}  # list alone carries no secret keys
    bank = _entry_obj(data, "bank", kmeta)
    assert bank is not None  # metadata opens — that is what list means
    with pytest.raises(InvalidTag):
        _dec(kmeta, bank["secret"], _aad("secret", bank["id"]))


# ---------------------------------------------------------------------------
# (b) in-scope access end-to-end (CLI + MCP are covered by the Phase 2A
# suite; here: bundle re-issue picks up entries added after enrollment)
# ---------------------------------------------------------------------------

def test_bundle_reissued_on_human_save(vault_path, stocked):
    token = enroll_agent(stocked, "reader", ["get:*"])
    stocked.add_entry(make_entry(service="gitlab", password="pw-gitlab"))
    session = open_agent_session(vault_path, token)
    assert session.get("gitlab")["password"] == "pw-gitlab"


# ---------------------------------------------------------------------------
# (c) revocation / disable / scope narrowing rotate keys
# ---------------------------------------------------------------------------

def test_revocation_rotates_keys_against_old_bundle(vault_path, stocked):
    token = enroll_agent(stocked, "doomed", ["list", "get:*"])
    _bk, bundle, _data = _extract_bundle(vault_path, token)
    old_kmeta = _b64d(bundle["kmeta"])
    old_deks = {eid: _b64d(t["dek_pw"]) for eid, t in bundle["targets"].items()}

    human = MyKey(CORRECT, vault_file=vault_path)
    human.unlock()
    revoke_agent(human, "doomed")

    data = json.load(open(vault_path))
    assert not any(s["id"] == "agent:doomed" for s in data["slots"])
    assert "doomed" not in (data.get("bundles") or {})
    # every previously readable entry was re-keyed: old keys are dead
    # against the LIVE file (entries added later are equally safe —
    # their keys were never in the bundle at all)
    for obj in data["entries"]:
        if obj["id"] in old_deks:
            with pytest.raises(InvalidTag):
                _dec(old_deks[obj["id"]], obj["secret"],
                     _aad("secret", obj["id"]))
            with pytest.raises(InvalidTag):
                _dec(old_kmeta, obj["meta"], _aad("meta", obj["id"]))
    with pytest.raises(AgentAuthError):
        open_agent_session(vault_path, token)
    # a second agent is unaffected
    other = enroll_agent(human, "other", ["get:github"])
    assert open_agent_session(vault_path, other).get("github")["password"] \
        == "pw-github"


def test_disable_rotates_keys_and_reenable_reissues(vault_path, stocked):
    token = enroll_agent(stocked, "temp", ["get:github"])
    _bk, bundle, _d = _extract_bundle(vault_path, token)
    gh_id = bundle["services"]["github"]
    old_dek = _b64d(bundle["targets"][gh_id]["dek_pw"])

    human = MyKey(CORRECT, vault_file=vault_path)
    human.unlock()
    set_agent_enabled(human, "temp", False)
    data = json.load(open(vault_path))
    gh = next(o for o in data["entries"] if o["id"] == gh_id)
    with pytest.raises(InvalidTag):  # cached bundle is stale on the live file
        _dec(old_dek, gh["secret"], _aad("secret", gh_id))
    with pytest.raises(AgentAuthError):
        open_agent_session(vault_path, token)
    set_agent_enabled(human, "temp", True)  # same token, fresh bundle
    assert open_agent_session(vault_path, token).get("github")["password"] \
        == "pw-github"


def test_scope_narrowing_rotates_removed_targets(vault_path, stocked):
    token = enroll_agent(stocked, "narrowing", ["list", "get:github", "get:bank"])
    _bk, bundle, _d = _extract_bundle(vault_path, token)
    bank_id = bundle["services"]["bank"]
    old_bank_dek = _b64d(bundle["targets"][bank_id]["dek_pw"])

    human = MyKey(CORRECT, vault_file=vault_path)
    human.unlock()
    set_agent_scopes(human, "narrowing", ["list", "get:github"])
    data = json.load(open(vault_path))
    bank = next(o for o in data["entries"] if o["id"] == bank_id)
    with pytest.raises(InvalidTag):
        _dec(old_bank_dek, bank["secret"], _aad("secret", bank_id))
    session = open_agent_session(vault_path, token)
    with pytest.raises(AgentScopeError):
        session.get("bank")
    assert session.get("github")["password"] == "pw-github"


def test_expired_agent_is_retired_at_human_unlock(vault_path, stocked):
    token = enroll_agent(stocked, "shortlived", ["list"], expires_days=1)
    stocked._agents["shortlived"]["expires_at"] = int(time.time()) - 5
    stocked._persist()
    with pytest.raises(AgentAuthError):  # client-side refusal pre-retirement
        open_agent_session(vault_path, token)
    MyKey(CORRECT, vault_file=vault_path).unlock()  # human-mediated rekey
    data = json.load(open(vault_path))
    assert not any(s["id"] == "agent:shortlived" for s in data["slots"])
    assert "shortlived" not in (data.get("bundles") or {})


# ---------------------------------------------------------------------------
# audit anchor attacks
# ---------------------------------------------------------------------------

def _anchored_vault(vault_path, stocked):
    token = enroll_agent(stocked, "wright", ["list"])
    open_agent_session(vault_path, token)
    MyKey(CORRECT, vault_file=vault_path).unlock()  # seals + anchors
    return token


def test_anchor_tamper_detected_at_human_unlock(vault_path, stocked):
    _anchored_vault(vault_path, stocked)
    anchor_path = vault_path + ".audit-anchor.json"
    anchor = json.load(open(anchor_path))
    anchor["head"] = "0" * 64
    json.dump(anchor, open(anchor_path, "w"))
    with pytest.raises(AuditAnchorError):
        MyKey(CORRECT, vault_file=vault_path).unlock()


def test_log_rollback_behind_anchor_detected(vault_path, stocked):
    token = _anchored_vault(vault_path, stocked)
    open_agent_session(vault_path, token)  # one more record
    MyKey(CORRECT, vault_file=vault_path).unlock()  # anchor advances
    audit_file = vault_path + ".audit.jsonl"
    lines = open(audit_file).read().splitlines()
    open(audit_file, "w").write("\n".join(lines[:-1]) + "\n")  # roll back
    with pytest.raises(AuditAnchorError):
        MyKey(CORRECT, vault_file=vault_path).unlock()


def test_log_and_anchor_rollback_detected_by_seal(vault_path, stocked):
    """Rolling the log AND its anchor back together (vault file left
    current) is caught by the core seal: the sealed head must still
    be in the chain, and re-sealing over a rollback is refused."""
    token = _anchored_vault(vault_path, stocked)
    anchor_path = vault_path + ".audit-anchor.json"
    audit_file = vault_path + ".audit.jsonl"
    old_anchor = open(anchor_path).read()
    old_lines = open(audit_file).read().splitlines()
    open_agent_session(vault_path, token)
    MyKey(CORRECT, vault_file=vault_path).unlock()  # seal + anchor advance
    # the combined rollback: log and anchor both restored to before
    open(anchor_path, "w").write(old_anchor)
    open(audit_file, "w").write("\n".join(old_lines) + "\n")
    with pytest.raises(AuditAnchorError):
        MyKey(CORRECT, vault_file=vault_path).unlock()


def test_agent_appends_after_anchor_are_normal(vault_path, stocked):
    token = _anchored_vault(vault_path, stocked)
    open_agent_session(vault_path, token)
    open_agent_session(vault_path, token)
    # anchored head is a prefix of the grown chain: unlock succeeds
    assert MyKey(CORRECT, vault_file=vault_path).unlock() is not None


def test_backoff_failures_are_audit_visible_but_refusals_are_not_appended(
        vault_path, stocked):
    token = enroll_agent(stocked, "wright", ["list"])
    guard = AgentGuard(vault_path, base_seconds=30.0, cap_seconds=60.0)
    bad = "mkag1.wright." + base64.urlsafe_b64encode(b"\x00" * 32).decode().rstrip("=")
    with pytest.raises(AgentAuthError):
        open_agent_session(vault_path, bad, guard=guard)
    records = read_audit(vault_path)
    assert any(r["agent"] == "wright" and r["action"] == "auth"
               and r["result"] == "deny" for r in records)
    count = len(records)
    with pytest.raises(AgentLockedError):
        open_agent_session(vault_path, token, guard=guard)
    with pytest.raises(AgentLockedError):
        open_agent_session(vault_path, token, guard=guard)
    # refusals inside the window did not grow the log (no DoS vector)
    assert len(read_audit(vault_path)) == count


# ---------------------------------------------------------------------------
# committed-ciphertext integrity, inbox binding, pending authentication
# ---------------------------------------------------------------------------

def test_committed_ciphertext_swap_detected(vault_path, stocked):
    data = json.load(open(vault_path))
    obj = data["entries"][0]
    raw = bytearray(base64.b64decode(obj["secret"]["ciphertext"]))
    raw[0] ^= 0xFF
    obj["secret"]["ciphertext"] = base64.b64encode(bytes(raw)).decode()
    json.dump(data, open(vault_path, "w"))
    with pytest.raises(VaultCorrupt, match="hash sealed in the vault core"):
        MyKey(CORRECT, vault_file=vault_path).unlock()


def test_inbox_key_substitution_detected(vault_path, stocked):
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey)
    from cryptography.hazmat.primitives.serialization import (
        Encoding, PublicFormat)
    data = json.load(open(vault_path))
    attacker_pub = X25519PrivateKey.generate().public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw)
    data["inbox_pub"] = base64.b64encode(attacker_pub).decode()
    json.dump(data, open(vault_path, "w"))
    with pytest.raises(VaultCorrupt):
        MyKey(CORRECT, vault_file=vault_path).unlock()


def test_agent_refuses_to_seal_to_substituted_inbox(vault_path, stocked):
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey)
    from cryptography.hazmat.primitives.serialization import (
        Encoding, PublicFormat)
    token = enroll_agent(stocked, "writer", ["write"])
    data = json.load(open(vault_path))
    attacker_pub = X25519PrivateKey.generate().public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw)
    data["inbox_pub"] = base64.b64encode(attacker_pub).decode()
    json.dump(data, open(vault_path, "w"))
    session = open_agent_session(vault_path, token)
    with pytest.raises(AgentAuthError):
        session.add_entry({"service": "x", "password": "y"})


def test_forged_pending_entry_is_not_accepted(vault_path, stocked):
    token = enroll_agent(stocked, "writer", ["write"])
    session = open_agent_session(vault_path, token)
    session.add_entry({"service": "real", "password": "pw-real"})
    # a file editor forges a second pending entry claiming the writer
    data = json.load(open(vault_path))
    forged = json.loads(json.dumps(
        next(o for o in data["entries"] if o.get("pending"))))
    forged["id"] = "f" * 32
    forged["pending"]["mac"] = "0" * 64
    data["entries"].append(forged)
    json.dump(data, open(vault_path, "w"))
    human = MyKey(CORRECT, vault_file=vault_path)
    human.unlock()
    assert human.get_password("real") == "pw-real"  # genuine one accepted
    assert len(human.list_entries()) == 3  # forged one was not
    assert forged["id"] in human._raw_pending  # left for inspection


# ---------------------------------------------------------------------------
# migration + downgrade
# ---------------------------------------------------------------------------

def _write_v2_vault(path, password, entries, agent_token_raw=None):
    """Fabricate a genuine Vault v2 file (format as shipped in 2A)."""
    vk = os.urandom(32)
    salt = os.urandom(16)
    kek = low_level.hash_secret_raw(
        secret=password.encode(), salt=salt, time_cost=3,
        memory_cost=65536, parallelism=4, hash_len=32,
        type=low_level.Type.ID)
    def slot(slot_id, wrapping):
        nonce = os.urandom(12)
        ct = AESGCM(wrapping).encrypt(nonce, vk, f"slot:{slot_id}".encode())
        return {"id": slot_id, "algo": "argon2id",
                "salt": base64.b64encode(salt).decode(),
                "time_cost": 3, "memory_cost": 65536, "parallelism": 4,
                "nonce": base64.b64encode(nonce).decode(),
                "ciphertext": base64.b64encode(ct).decode()}
    slots = [slot("master", kek)]
    if agent_token_raw is not None:
        asalt = os.urandom(16)
        akek = low_level.hash_secret_raw(
            secret=agent_token_raw, salt=asalt, time_cost=3,
            memory_cost=65536, parallelism=4, hash_len=32,
            type=low_level.Type.ID)
        nonce = os.urandom(12)
        ct = AESGCM(akek).encrypt(nonce, vk, b"slot:agent:old")
        slots.append({"id": "agent:old", "algo": "argon2id",
                      "salt": base64.b64encode(asalt).decode(),
                      "time_cost": 3, "memory_cost": 65536, "parallelism": 4,
                      "nonce": base64.b64encode(nonce).decode(),
                      "ciphertext": base64.b64encode(ct).decode()})
    payload = {"entries": entries, "agents": {}, "audit_head": ""}
    nonce = os.urandom(12)
    ct = AESGCM(vk).encrypt(nonce, json.dumps(payload).encode(), b"MKVLT")
    doc = {"format": "MKVLT", "version": 2, "slots": slots,
           "nonce": base64.b64encode(nonce).decode(),
           "ciphertext": base64.b64encode(ct).decode()}
    with open(path, "w") as f:
        json.dump(doc, f)
    return vk


def test_v2_migration_rotates_vk_and_strips_backup_slots(vault_path):
    raw_token = b"\x07" * 32
    token = "mkag1.old." + base64.urlsafe_b64encode(raw_token).decode().rstrip("=")
    old_vk = _write_v2_vault(
        vault_path, CORRECT,
        [{"id": "a" * 32, "service": "github", "password": "pw-1"}],
        agent_token_raw=raw_token)
    app = MyKey(CORRECT, vault_file=vault_path)
    assert app.get_password("github") == "pw-1"
    assert app._migrated_from == 2
    data = json.load(open(vault_path))
    assert data["version"] == 3
    # the old vault key is useless against the migrated file
    with pytest.raises(InvalidTag):
        _dec(old_vk, data["core"], _aad("core", data["vault_id"]))
    # the migration backup kept human slots only — no agent slot can
    # unwrap anything from it
    backup = json.load(open(vault_path + ".v2.bak"))
    assert not any(s["id"].startswith("agent:") for s in backup["slots"])
    # the retired agent token is dead on the live vault
    with pytest.raises(AgentAuthError):
        open_agent_session(vault_path, token)


def test_version_tampering_is_rejected(vault_path, stocked):
    data = json.load(open(vault_path))
    data["version"] = 99
    json.dump(data, open(vault_path, "w"))
    with pytest.raises(VaultCorrupt):
        MyKey(CORRECT, vault_file=vault_path).unlock()
    data["version"] = 2  # relabel a v3 file as v2: no silent downgrade
    json.dump(data, open(vault_path, "w"))
    with pytest.raises(VaultCorrupt):
        MyKey(CORRECT, vault_file=vault_path).unlock()
