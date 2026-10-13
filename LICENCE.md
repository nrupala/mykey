# MyKey — free version and licence

MyKey is free to use. A one-time licence removes the size limits.
This page explains exactly what the limits are, what a licence is,
and what happens to your passwords in every case. Short version:
**the limits count how much you store — they never touch your
security.** Encryption, two-factor backups, sync, device pairing,
password rotation, export — all of it works in the free version,
exactly as in the licensed one.

## The free version

- Up to **50 passwords** in a vault.
- Up to **4 connections** enrolled on a vault (see "Connections"
  below).

That is all that is limited. Everything else — every security
feature, every platform, sync, backups, import and export — is
fully available for free.

## What a licence unlocks

- **Unlimited passwords.**
- Up to **20 connections** enrolled on the licensed vault.

A licence is a one-time purchase. There is no subscription for
the app itself and no account to sign in to.

## Connections — one pool

Devices you enroll for sync and backup, agents you authorize, and
browsers you pair all draw from **one shared pool of connections**
on each vault, in any mix: 2 phones + 1 agent + 1 browser is 4
connections. The free pool is 4; a licence raises it to 20 (your
licence key states its own number).

Counting is per vault — it is the devices, agents and browsers
enrolled **on that vault**. Backup and cloud destinations you pair
a vault with are not connections and are never counted.

## If you hit a limit

Nothing bad happens to your data:

- **Adding pauses, nothing else does.** If your vault already
  holds more than the free limit — say you stored 60 passwords
  while licensed, or restored a bigger vault — it still opens
  fully. You can read, copy, edit and export everything. Only
  adding a *new* password (or enrolling a new connection) waits,
  until you enter a licence or delete something to make room.
- **Imports fill up to the limit.** If you import 10 passwords
  with room for 6, the 6 are imported and MyKey tells you exactly
  how many were held back and why. Enter a licence and import the
  same file again — the ones already in are skipped as duplicates
  and the rest come in.
- **Revoking frees a place at once.** Remove a device, agent or
  browser you no longer use and its connection place is free
  immediately.

The limits are a fairness limit enforced **inside the app, on your
device, offline**. MyKey does not phone home, and there is no
activation server checking up on you.

## Your licence key

A licence key is a signed statement (it starts with `MKLIC1.`),
issued by the **MyKey Licence Authority** — a cryptographic key
held by 2351485 ALBERTA INC. Your app carries the matching public
key and checks the signature on your device, offline. Anyone can
confirm a key is genuine; nobody can forge one.

- Paste your key under **Settings / About → Enter a licence key**
  (command line: `licence-activate`). MyKey tells you in plain
  words whether it checked out.
- The key is stored **inside your vault** (encrypted with it, so
  it travels with the vault to your other devices) and in a
  **slot on this device** (so a new vault you create here starts
  licensed). Either copy on its own is enough.
- The key is a signed statement, not a password. It is safe to
  keep a copy of it with your purchase email.

### The passcode on your licence

Each licence also carries a **passcode**, printed in its signed
statement. It is computed once, at purchase, from your email, the
payment date, your date of birth, and a random serial number that
only we hold. Those details let us *find* your licence again —
they are never used to create keys, and your date of birth is
never written into the key, the statement, or any file you
receive. We keep a salted fingerprint of the three details in our
licence registry so the passcode (and a lost key) can be recovered
without storing the details themselves.

## If you lose your licence key

Email **info@aimlds.org** from the address you bought with, and
include your **email, payment date, and date of birth**, plus your
payment receipt if you have it. We look your licence up and
re-send the key **only to the email address on file** — never to a
different address, however the request arrives. (A self-serve
recovery page is planned for the product website; until then,
email is the way.)

## Checking a licence yourself (for the technically curious)

Alongside your key you receive a statement file
(`<licence>.statement.json`) and its detached OpenPGP signature
(`<licence>.statement.json.asc`), signed by the MyKey Licence
Authority (fingerprint
`EE62F41972E84A9ABDEDF14A565D3A0C9B65B996`). The authority's public
key is published inside the app (the `licensing` module) and on
the product website. With GnuPG:

```
gpg --import mykey-licence-authority-public.asc
gpg --verify <licence>.statement.json.asc <licence>.statement.json
```

A "Good signature" result means the statement — your licence
number, passcode and connection count — is exactly what was
issued.

## Buying, and the tip jar

- **Buy a licence:** the button in Settings / About opens the
  purchase page on our website (usemykey.com). One-time payment,
  pay what you want above the floor price.
- **Android note:** inside the Android app, the Buy button does
  not open a web checkout for the unlock (Google Play rules). It
  shows you where to buy on the website from another device; when
  MyKey is listed on Google Play, in-app purchase will plug into
  the same place. Pasting a licence key works in every build,
  always.
- **Tip jar:** also in Settings / About, and deliberately
  separate. Tips are thanks, not a purchase — they unlock nothing
  and nothing is held back without one.

## Authority setup (internal note)

The authority keypair was generated once with GnuPG (ed25519,
certify+sign, no expiry). The private key and revocation
certificate live only in the company's licensing folder with
restricted permissions — never in this repository. The issuer tool
(`tools/issue_licence.py`) signs the compact `MKLIC1.` token with
the authority's raw Ed25519 scalar, loaded from a PEM derived
one-time from the GPG secret export (`derive-pem` subcommand);
every issuance cross-checks the PEM against the GPG home and
refuses on any mismatch or unsafe file permission.
