# Proprietary — Copyright (c) 2026 2351485 ALBERTA INC. All rights reserved.
"""Tests for tools/stripe_issuer.py — release-gate F-MK-1/F-MK-2.

F-MK-1: the issuer dedupes by checkout session id — a session
that already minted a licence (crash after mint, duplicate
delivery) never mints or emails a second one.
F-MK-2: recorded Stripe disputes are applied to the registry —
created flags the licence, closed-lost revokes it as a
chargeback, closed-won clears the flag.

KV and the mint/email steps are stubbed; registries are temp
files. No network, no real registry, no licence authority key.
"""
import importlib.util
import json
import os

import pytest

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load_issuer():
    spec = importlib.util.spec_from_file_location(
        "stripe_issuer", os.path.join(_ROOT, "tools", "stripe_issuer.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


si = _load_issuer()


class FakeKV:
    def __init__(self):
        self.store = {}

    def list(self, prefix):
        return sorted(k for k in self.store if k.startswith(prefix))

    def get(self, key):
        return json.loads(json.dumps(self.store[key]))

    def put(self, key, obj):
        self.store[key] = json.loads(json.dumps(obj))


@pytest.fixture()
def issuer(tmp_path, monkeypatch):
    kv = FakeKV()
    monkeypatch.setattr(si, "kv_list", kv.list)
    monkeypatch.setattr(si, "kv_get", kv.get)
    monkeypatch.setattr(si, "kv_put", kv.put)
    test_reg = str(tmp_path / "registry-test.jsonl")
    prod_reg = str(tmp_path / "registry.jsonl")
    monkeypatch.setattr(si, "TEST_REGISTRY", test_reg)
    monkeypatch.setattr(si, "PROD_REGISTRY", prod_reg)
    calls = {"issue": 0, "email": 0}

    def fake_issue(order, registry, out_dir):
        calls["issue"] += 1
        licence_id = "lic-fake000000000001"
        rec = {
            "licence_id": licence_id,
            "licensee": order["email"],
            "payment_date": order.get("payment_date", "2026-10-19"),
            "passcode": "FAKE",
            "status": "active",
            "source": "stripe-web",
            "stripe_session": order["session_id"],
            "stripe_payment_intent": order.get("payment_intent"),
        }
        records = si._read_registry(registry)
        records.append(rec)
        si._rewrite_registry(registry, records)
        return licence_id, rec

    def fake_email(order, licence_id, record, out_dir):
        calls["email"] += 1

    monkeypatch.setattr(si, "_issue", fake_issue)
    monkeypatch.setattr(si, "_send_licence_email", fake_email)
    return kv, calls, test_reg


def _order(session="cs_test_new", **over):
    order = {
        "kind": "licence", "tier": "licence_pwyw",
        "session_id": session, "payment_intent": "pi_test_new",
        "subscription": None, "email": "buyer@example.com",
        "amount_total": 4900, "currency": "usd",
        "payment_status": "paid", "livemode": False,
        "received_at": "2026-10-19T00:00:00Z",
        "status": "awaiting_issue",
    }
    order.update(over)
    return order


def _write_registry(path, records):
    si._rewrite_registry(path, records)


def _read(path):
    return si._read_registry(path)


def test_dedupe_no_second_mint(issuer):
    kv, calls, test_reg = issuer
    _write_registry(test_reg, [{
        "licence_id": "lic-existing000001", "status": "active",
        "source": "stripe-web", "stripe_session": "cs_test_dup",
        "stripe_payment_intent": "pi_test_dup",
    }])
    kv.store["order:cs_test_dup"] = _order(
        "cs_test_dup", payment_intent="pi_test_dup")
    si.process_order("order:cs_test_dup", False, lambda m: None)
    assert calls["issue"] == 0
    assert calls["email"] == 0
    order = kv.store["order:cs_test_dup"]
    assert order["status"] == "issued"
    assert order["licence_id"] == "lic-existing000001"
    assert len(_read(test_reg)) == 1


def test_new_session_mints_once(issuer):
    kv, calls, test_reg = issuer
    kv.store["order:cs_test_new"] = _order()
    si.process_order("order:cs_test_new", False, lambda m: None)
    assert calls["issue"] == 1
    assert calls["email"] == 1
    assert kv.store["order:cs_test_new"]["status"] == "issued"
    assert len(_read(test_reg)) == 1


def _dispute(event, status, session="cs_test_disp", pi="pi_test_disp",
             dispute_id="dp_test_1"):
    return {
        "dispute_id": dispute_id, "charge_id": "ch_test_disp",
        "payment_intent": pi, "session_id": session, "event": event,
        "dispute_status": status, "reason": "fraudulent",
        "amount": 4900, "currency": "usd", "livemode": False,
        "received_at": "2026-10-19T01:00:00Z",
        "status": "awaiting_issuer",
    }


def _active_record(**over):
    rec = {
        "licence_id": "lic-disp0000000001", "status": "active",
        "source": "stripe-web", "stripe_session": "cs_test_disp",
        "stripe_payment_intent": "pi_test_disp",
    }
    rec.update(over)
    return rec


def test_dispute_created_flags_licence(issuer):
    kv, calls, test_reg = issuer
    _write_registry(test_reg, [_active_record()])
    kv.store["dispute:dp_test_1:created"] = _dispute(
        "created", "needs_response")
    si.process_dispute("dispute:dp_test_1:created", False, lambda m: None)
    rec = _read(test_reg)[0]
    assert rec["disputed"] is True
    assert rec["dispute_id"] == "dp_test_1"
    assert rec["status"] == "active"
    assert kv.store["dispute:dp_test_1:created"]["status"] == "processed"


def test_dispute_closed_lost_revokes_as_chargeback(issuer):
    kv, calls, test_reg = issuer
    _write_registry(test_reg, [_active_record(disputed=True)])
    kv.store["dispute:dp_test_1:closed"] = _dispute("closed", "lost")
    si.process_dispute("dispute:dp_test_1:closed", False, lambda m: None)
    rec = _read(test_reg)[0]
    assert rec["status"] == "revoked"
    assert rec["revoke_reason"] == "stripe chargeback (dispute lost)"
    assert rec["dispute_outcome"] == "lost"


def test_dispute_closed_won_clears_flag(issuer):
    kv, calls, test_reg = issuer
    _write_registry(test_reg, [_active_record(disputed=True)])
    kv.store["dispute:dp_test_1:closed"] = _dispute("closed", "won")
    si.process_dispute("dispute:dp_test_1:closed", False, lambda m: None)
    rec = _read(test_reg)[0]
    assert rec["disputed"] is False
    assert rec["dispute_outcome"] == "won"
    assert rec["status"] == "active"


def test_dispute_no_matching_licence_flagged(issuer):
    kv, calls, test_reg = issuer
    _write_registry(test_reg, [_active_record()])
    kv.store["dispute:dp_x:created"] = _dispute(
        "created", "needs_response", session="cs_other", pi="pi_other",
        dispute_id="dp_x")
    si.process_dispute("dispute:dp_x:created", False, lambda m: None)
    assert kv.store["dispute:dp_x:created"]["status"] == \
        "no_matching_licence"
    assert "disputed" not in _read(test_reg)[0]
