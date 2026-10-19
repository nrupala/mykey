# Proprietary — Copyright (c) 2026 2351485 ALBERTA INC. All rights reserved.
#
# This file is part of the proprietary core (licence issuance
# tooling). It is NOT licensed under Apache 2.0, MIT, or any other
# open licence. No patent licence is granted by this file; all
# patent rights are expressly reserved. See LICENSING.md for the
# licence map.

"""Stripe order issuer — ADMIN TOOLING. Never shipped to buyers.

The second half of MyKey's web checkout (the first half is the
usemykey.com Worker, nrupala/usemykey-site):

  buyer pays on a Stripe Payment Link
    -> Stripe calls POST /stripe/webhook on the site Worker
    -> the Worker verifies Stripe's signature and records the
       order (or the refund) in the MYKEY_ORDERS Cloudflare KV
       namespace
    -> THIS TOOL polls that namespace, and for each paid licence
       order mints the buyer's key with tools/issue_licence.py
       (which enforces every authority check), records the Stripe
       references on the registry record, and emails the key to
       the buyer from info@aimlds.org
    -> for each refund record it marks the licence REVOKED in
       the registry

Signing happens here, in the environment where the licence
authority's private key already lives
(~/workspace/corporate/licensing/, 0700/0600). The key never
enters the Worker, a repository, a log, or this tool's output.

LIVE vs TEST. Orders carry Stripe's own `livemode` flag. Live
orders are cross-checked against Stripe's API (through the
connected Stripe connector) before anything is minted — session
paid, amounts and payment reference must match — and are written
to the production registry. Test orders go to a separate test
registry (registry-test.jsonl beside the production one) and are
emailed only as pipeline proofs.

WEB-SALE IDENTITY INPUTS — the one adaptation from the direct
sale flow, named plainly (2026-10-19). issue_licence.py computes
a licence's passcode and recovery hash from three buyer inputs:
email, payment date, and a third identifying input (a date of
birth for direct sales). A web buyer provides no date of birth,
and none is invented. For Stripe sales this tool passes the
Stripe payment reference (the payment_intent id) in that third
slot. The three inputs for a web licence are therefore: buyer
email, payment date, and the Stripe payment reference — the
reference is on the buyer's Stripe receipt and in our Stripe
records, and the trio identifies the licence and authorizes its
reissue exactly as the direct-sale trio does. The registry keeps
its discipline unchanged: only a salted hash of the inputs is
stored, never the inputs' sensitive forms.

Refunds: the registry record gains status "revoked" with the
time and reason. The shipped clients verify licences offline
(there is no activation server by design), so revocation bites
at the registry: a revoked licence is never reissued, and
support treats it as void.

Idempotency (release-gate F-MK-1): Stripe delivery is
at-least-once and this tool can crash mid-run, so one payment
must never mint two licences. The Worker half is write-once at
the recorder; this half dedupes by checkout session id: before
minting, the selected registry is checked for a record already
carrying the order's session — if one exists, the order is
marked issued with that existing licence id and nothing is
minted or emailed again.

Disputes (release-gate F-MK-2): the Worker records
charge.dispute.created / charge.dispute.closed events that
resolve to a MyKey order as dispute: records. This tool applies
them to the registry: a created dispute flags the licence
(disputed, with the dispute id); a dispute closed lost revokes
the licence with reason "stripe chargeback (dispute lost)";
closed won clears the flag. Refund and dispute records exist
only for charges that resolve to a MyKey order — other product
lines on the shared account never reach this tool.

Usage:
  python3 tools/stripe_issuer.py [--dry-run]

Environment:
  MYKEY_ORDERS_KV_ID   KV namespace id (default: the production
                        namespace created 2026-10-19)
  STRIPE_CLI            connector CLI for live cross-checks
                        (default /opt/hatch/bin/stripe)
  GMAIL_CLI             mail CLI (default hatch_gws_cli)
"""

import argparse
import json
import os
import subprocess
import sys
import urllib.parse
import urllib.request
import urllib.error
from datetime import datetime, timezone

sys.path.insert(0, "/opt/hatch/skills/skill-creator/bin")
from dynamic_credentials import (  # noqa: E402
    add_surrogate_to_request, read_json_response)

CF_ACCOUNT = "2edd59d09fd816187b47afbb9ea43af1"
DEFAULT_KV_ID = "62c92c6580d949bb99f813deae591ed9"
CORPORATE_DIR = os.path.join(
    os.path.expanduser("~"), "workspace", "corporate", "licensing")
PROD_REGISTRY = os.path.join(CORPORATE_DIR, "registry.jsonl")
TEST_REGISTRY = os.path.join(CORPORATE_DIR, "registry-test.jsonl")
PROD_OUT_DIR = os.path.join(CORPORATE_DIR, "issued")
TEST_OUT_DIR = os.path.join(CORPORATE_DIR, "issued-test")
TOOLS_DIR = os.path.dirname(os.path.abspath(__file__))
STRIPE_ACCOUNT = "acct_1UQdZREAiA4GKFhA"


class IssuerError(Exception):
    pass


# -- Cloudflare KV -------------------------------------------------

def _cf(method, path, data=None, ctype=None):
    req = urllib.request.Request(
        "https://api.cloudflare.com" + path, method=method, data=data,
        headers={"Content-Type": ctype} if ctype else {})
    add_surrogate_to_request(
        req, "custom.cloudflare", allowed_hosts=["api.cloudflare.com"])
    try:
        with urllib.request.urlopen(req) as resp:
            raw = resp.read()
            if (resp.headers.get("Content-Type") or "").startswith(
                    "application/json"):
                return resp.status, json.loads(raw or b"{}")
            return resp.status, raw.decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        raise IssuerError(
            f"Cloudflare {method} {path}: HTTP {e.code} "
            f"{e.read()[:300].decode('utf-8', 'replace')}")


def kv_list(prefix):
    ns = os.environ.get("MYKEY_ORDERS_KV_ID", DEFAULT_KV_ID)
    st, r = _cf(
        "GET", f"/client/v4/accounts/{CF_ACCOUNT}/storage/kv/"
        f"namespaces/{ns}/keys?prefix={urllib.parse.quote(prefix)}"
        f"&limit=1000")
    if st != 200:
        raise IssuerError(f"KV list failed: {r}")
    return [k["name"] for k in r.get("result", [])]


def kv_get(key):
    ns = os.environ.get("MYKEY_ORDERS_KV_ID", DEFAULT_KV_ID)
    st, r = _cf(
        "GET", f"/client/v4/accounts/{CF_ACCOUNT}/storage/kv/"
        f"namespaces/{ns}/values/{urllib.parse.quote(key, safe='')}")
    if st != 200:
        raise IssuerError(f"KV get {key} failed")
    return json.loads(r)


def kv_put(key, obj):
    ns = os.environ.get("MYKEY_ORDERS_KV_ID", DEFAULT_KV_ID)
    st, _r = _cf(
        "PUT", f"/client/v4/accounts/{CF_ACCOUNT}/storage/kv/"
        f"namespaces/{ns}/values/{urllib.parse.quote(key, safe='')}",
        data=json.dumps(obj).encode(), ctype="text/plain")
    if st != 200:
        raise IssuerError(f"KV put {key} failed: HTTP {st}")


# -- registry --------------------------------------------------------

def _read_registry(path):
    if not os.path.exists(path):
        return []
    out = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out


def _rewrite_registry(path, records):
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "a", encoding="utf-8") as f:
        for rec in records:
            f.write(json.dumps(rec, sort_keys=True) + "\n")
    os.replace(tmp, path)
    os.chmod(path, 0o600)


def _annotate_registry(path, licence_id, fields):
    records = _read_registry(path)
    hit = None
    for rec in records:
        if rec.get("licence_id") == licence_id:
            rec.update(fields)
            hit = rec
    if hit is None:
        raise IssuerError(f"licence {licence_id} not found in {path}")
    _rewrite_registry(path, records)
    return hit


# -- Stripe cross-check (live orders only) ---------------------------

def stripe_session(session_id):
    cli = os.environ.get("STRIPE_CLI", "/opt/hatch/bin/stripe")
    args = json.dumps({
        "stripe_api_operation_id": "GetCheckoutSessionsSession",
        "stripe_context": STRIPE_ACCOUNT, "livemode": True,
        "parameters": {"id": session_id}})
    run = subprocess.run(
        [cli, "call-tool", "--name", "stripe_api_read",
         "--arguments-json", args],
        capture_output=True, text=True, timeout=120)
    if run.returncode != 0:
        raise IssuerError(
            f"Stripe connector read failed: {run.stderr.strip()[:300]}")
    outer = json.loads(run.stdout)
    return json.loads(outer["result"]["content"][0]["text"])


# -- issuance ----------------------------------------------------------

def _issue(order, registry, out_dir):
    """Run the issuer tool for one order; return (licence_id, record)."""
    payment_ref = order.get("payment_intent")
    if not payment_ref:
        raise IssuerError("order has no payment reference")
    cmd = [sys.executable, os.path.join(TOOLS_DIR, "issue_licence.py"),
           "issue", "--email", order["email"],
           "--payment-date", order["payment_date"],
           # Web-sale adaptation (see module docstring): the
           # Stripe payment reference takes the third identity
           # slot. No date of birth exists for a web buyer and
           # none is invented.
           "--dob", payment_ref,
           "--out-dir", out_dir, "--registry", registry]
    run = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    if run.returncode != 0:
        raise IssuerError(
            f"issue_licence failed: {run.stderr.strip()[:400]}")
    licence_id = None
    for line in run.stdout.splitlines():
        if line.startswith("licence issued:"):
            licence_id = line.split()[2]
    if not licence_id:
        raise IssuerError("issuer ran but no licence id was parsed")
    record = _annotate_registry(registry, licence_id, {
        "source": "stripe-web",
        "stripe_session": order["session_id"],
        "stripe_payment_intent": payment_ref,
        "stripe_amount_total": order.get("amount_total"),
        "stripe_currency": order.get("currency"),
    })
    return licence_id, record


def _send_licence_email(order, licence_id, record, out_dir):
    key_path = os.path.join(out_dir, licence_id + ".licence-key.txt")
    with open(key_path, "r", encoding="utf-8") as f:
        key_text = f.read().strip()
    test = order.get("livemode") is False
    subject = ("[TEST] Your MyKey licence key" if test
               else "Your MyKey licence key")
    lines = []
    if test:
        lines += ["This is a TEST of the MyKey licence delivery "
                  "pipeline — no real payment was made and this key "
                  "was minted into the test registry.", ""]
    lines += [
        "Thank you for buying a MyKey licence.",
        "",
        "Your licence key (keep this email):",
        "",
        key_text,
        "",
        "Paste it into MyKey once — Settings, Licence — on any "
        "device. The key is kept inside your encrypted vault, so "
        "it travels with your vault to your other devices: "
        "unlimited passwords and 20 connections in total.",
        "",
        f"Licence ID: {licence_id}",
        f"Your licence passcode: {record['passcode']}",
        "",
        "Lost your key later? We can re-issue it to this email "
        "address from your purchase details: this email address, "
        "the payment date "
        f"({record['payment_date']}), and your Stripe payment "
        "reference "
        f"({order.get('payment_intent')}) — all three are on your "
        "Stripe receipt. Or write to us with the receipt and we "
        "will sort it out.",
        "",
        "Support: info@aimlds.org",
        "",
        "MyKey · 2351485 ALBERTA INC., Calgary, Alberta, Canada",
    ]
    cli = os.environ.get("GMAIL_CLI", "hatch_gws_cli")
    run = subprocess.run(
        [cli, "gmail", "+send", "--from", "info@aimlds.org",
         "--to", order["email"], "--subject", subject,
         "--body", "\n".join(lines)],
        capture_output=True, text=True, timeout=180)
    if run.returncode != 0:
        raise IssuerError(
            f"licence email send failed: {run.stderr.strip()[:300]}")


# -- order processing ----------------------------------------------------

def process_order(key, dry_run, log):
    order = kv_get(key)
    if order.get("status") != "awaiting_issue":
        return
    kind = order.get("kind")
    if kind == "tip":
        order["status"] = "recorded"
        log(f"{key}: patron tip recorded (no licence to issue)")
        if not dry_run:
            kv_put(key, order)
        return
    if kind != "licence":
        order["status"] = "needs_attention"
        log(f"{key}: UNKNOWN kind {kind!r} — flagged needs_attention")
        if not dry_run:
            kv_put(key, order)
        return
    if not order.get("email"):
        order["status"] = "needs_attention"
        log(f"{key}: licence order without buyer email — flagged")
        if not dry_run:
            kv_put(key, order)
        return

    live = order.get("livemode") is not False
    if live:
        session = stripe_session(order["session_id"])
        problems = []
        if session.get("payment_status") != "paid":
            problems.append("Stripe session is not paid")
        if session.get("amount_total") != order.get("amount_total"):
            problems.append("amount differs from Stripe's record")
        if session.get("payment_intent") != order.get("payment_intent"):
            problems.append("payment reference differs from Stripe's")
        if problems:
            order["status"] = "needs_attention"
            order["attention_reason"] = "; ".join(problems)
            log(f"{key}: LIVE cross-check FAILED — {problems}")
            if not dry_run:
                kv_put(key, order)
            return
        order["payment_date"] = datetime.fromtimestamp(
            session["created"], timezone.utc).strftime("%Y-%m-%d")
        registry, out_dir = PROD_REGISTRY, PROD_OUT_DIR
    else:
        order["payment_date"] = order["received_at"][:10]
        registry, out_dir = TEST_REGISTRY, TEST_OUT_DIR

    # F-MK-1 dedupe: if this session already minted a licence
    # (the issuer crashed after minting but before marking the
    # order, or a duplicate delivery re-queued it), never mint
    # a second one. Mark the order issued with the EXISTING
    # licence id; send no further email.
    for r in _read_registry(registry):
        if r.get("stripe_session") == order["session_id"]:
            order["licence_id"] = r["licence_id"]
            order["licence_status"] = r.get("status")
            order["status"] = "issued"
            order["dedupe_note"] = (
                "session already in registry as "
                f"{r['licence_id']} — no new licence minted, "
                "no email sent")
            log(f"{key}: DEDUPE — session already issued as "
                f"{r['licence_id']} ({r.get('status')}); order "
                "marked issued, no new mint, no email")
            if not dry_run:
                kv_put(key, order)
            return

    if dry_run:
        log(f"{key}: DRY RUN — would issue to {order['email']} "
            f"({'live' if live else 'test'} registry)")
        return
    licence_id, record = _issue(order, registry, out_dir)
    order["licence_id"] = licence_id
    try:
        _send_licence_email(order, licence_id, record, out_dir)
        order["status"] = "issued"
        log(f"{key}: licence {licence_id} issued + emailed to "
            f"{order['email']} ({'live' if live else 'test'})")
    except IssuerError as exc:
        order["status"] = "issue_email_failed"
        order["attention_reason"] = str(exc)
        log(f"{key}: licence {licence_id} issued but EMAIL FAILED: {exc}")
    kv_put(key, order)


def process_revoke(key, dry_run, log):
    rec = kv_get(key)
    if rec.get("status") != "awaiting_revoke":
        return
    live = rec.get("livemode") is not False
    registry = PROD_REGISTRY if live else TEST_REGISTRY
    records = _read_registry(registry)
    target = None
    for r in records:
        if r.get("stripe_payment_intent") == rec.get("payment_intent"):
            target = r
    if target is None:
        # Fall back to the KV order that carried this payment ref.
        for okey in kv_list("order:"):
            o = kv_get(okey)
            if o.get("payment_intent") == rec.get("payment_intent") \
                    and o.get("licence_id"):
                for r in records:
                    if r.get("licence_id") == o["licence_id"]:
                        target = r
    if target is None:
        rec["status"] = "no_matching_licence"
        log(f"{key}: refund with no matching licence — flagged")
        if not dry_run:
            kv_put(key, rec)
        return
    if dry_run:
        log(f"{key}: DRY RUN — would revoke {target['licence_id']}")
        return
    target["status"] = "revoked"
    target["revoked_at"] = datetime.now(timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ")
    target["revoke_reason"] = "stripe charge.refunded"
    target["stripe_charge"] = rec.get("charge_id")
    _rewrite_registry(registry, records)
    rec["status"] = "processed"
    rec["licence_id"] = target["licence_id"]
    kv_put(key, rec)
    log(f"{key}: licence {target['licence_id']} marked REVOKED in "
        f"{'production' if live else 'test'} registry")


def process_dispute(key, dry_run, log):
    """Apply one recorded Stripe dispute to the registry (F-MK-2).

    created  -> flag the licence disputed (id + status + time)
    closed lost -> revoke with reason "stripe chargeback
                   (dispute lost)" (an already-revoked licence
                   keeps its original revocation; the dispute
                   outcome is still recorded on it)
    closed won  -> clear the disputed flag, record the outcome
    """
    rec = kv_get(key)
    if rec.get("status") != "awaiting_issuer":
        return
    live = rec.get("livemode") is not False
    registry = PROD_REGISTRY if live else TEST_REGISTRY
    records = _read_registry(registry)
    target = None
    for r in records:
        if rec.get("session_id") \
                and r.get("stripe_session") == rec["session_id"]:
            target = r
            break
    if target is None and rec.get("payment_intent"):
        for r in records:
            if r.get("stripe_payment_intent") \
                    == rec.get("payment_intent"):
                target = r
                break
    if target is None:
        rec["status"] = "no_matching_licence"
        log(f"{key}: dispute with no matching licence — flagged")
        if not dry_run:
            kv_put(key, rec)
        return
    if dry_run:
        log(f"{key}: DRY RUN — would record dispute "
            f"{rec.get('event')} on {target['licence_id']}")
        return
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    if rec.get("event") == "created":
        # A late-created record for an already-decided dispute
        # must not re-flag it.
        if not target.get("dispute_outcome"):
            target["disputed"] = True
            target["dispute_id"] = rec.get("dispute_id")
            target["dispute_status"] = rec.get("dispute_status")
            target["disputed_at"] = now
        outcome = "flagged disputed"
    elif rec.get("event") == "closed":
        target["dispute_id"] = rec.get("dispute_id")
        target["dispute_outcome"] = rec.get("dispute_status")
        target["dispute_closed_at"] = now
        if rec.get("dispute_status") == "lost":
            target["disputed"] = True
            if target.get("status") != "revoked":
                target["status"] = "revoked"
                target["revoked_at"] = now
                target["revoke_reason"] = \
                    "stripe chargeback (dispute lost)"
            outcome = "closed lost — licence revoked (chargeback)"
        elif rec.get("dispute_status") == "won":
            target["disputed"] = False
            outcome = "closed won — dispute flag cleared"
        else:
            outcome = f"closed ({rec.get('dispute_status')}) recorded"
    else:
        rec["status"] = "needs_attention"
        log(f"{key}: unknown dispute event {rec.get('event')!r} "
            "— flagged needs_attention")
        kv_put(key, rec)
        return
    _rewrite_registry(registry, records)
    rec["status"] = "processed"
    rec["licence_id"] = target["licence_id"]
    kv_put(key, rec)
    log(f"{key}: dispute {rec.get('event')} on licence "
        f"{target['licence_id']}: {outcome} "
        f"({'production' if live else 'test'} registry)")


def main(argv=None):
    p = argparse.ArgumentParser(
        description="MyKey Stripe order issuer (admin tooling — "
                    "see the module docstring)")
    p.add_argument("--dry-run", action="store_true",
                   help="report what would happen; change nothing")
    args = p.parse_args(argv)

    def log(msg):
        print(msg, flush=True)

    try:
        for key in kv_list("order:"):
            process_order(key, args.dry_run, log)
        for key in kv_list("revoke:"):
            process_revoke(key, args.dry_run, log)
        for key in kv_list("dispute:"):
            process_dispute(key, args.dry_run, log)
    except IssuerError as exc:
        print(f"❌ {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
