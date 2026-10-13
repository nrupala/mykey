<!-- Canonical in-app help text for MyKey. This file is the single
     source: the desktop app shows it from the Help menu, and the
     phone / web app carries a byte-for-byte copy in src/content/.
     Edit here first, then re-mirror. Plain words on purpose. -->

# How MyKey works

## The short version

- MyKey keeps all your passwords in one locked file, called a **vault**.
- One master password opens the vault. Nothing else can.
- There is no account and no server. MyKey works fully offline.
- Your passwords are scrambled (encrypted) before they are saved. Anyone who gets the file sees only scrambled data.
- We cannot see your passwords. We cannot reset your master password. There is no back door.

## Your vault

Your vault is a single file. It lives on this device.

Inside the vault, each password is an **entry**. An entry can hold:

- the service or app name, like a bank or a shop
- your username for it
- the password
- the website address
- notes
- a sign-in code setup, if the service uses one (see "Sign-in codes" below)

You can mark an entry as a favourite, add **tags** (short labels like "banking" or "family"), and search by name, username, website, notes, or tag.

Nothing in the vault is readable while it is locked. When you lock the app, the keys are dropped from memory.

## Your master password

Your master password is the key to the vault.

- It must be at least 12 characters. Longer is stronger. A line from a song or a few words strung together works well.
- Nobody can reset it for you — not us, not support. That is deliberate. A reset button for you would be a way in for someone else.
- If you forget it, your **recovery words** are the way back in (next section).
- You can change the master password any time from Settings. Your recovery words still work after a change.

## Your recovery words

When you set up recovery, MyKey shows you **12 words**, in order. These words are a second key to your vault.

- Write them on paper. Keep the paper somewhere safe, like with your important documents.
- Never share them. Anyone who has the words can open your vault.
- Never type them into a website, and never take a photo of them for a cloud album. Paper is safest.
- You use them if you forget your master password, or on a new device.
- You can replace the words any time from Settings. The old words stop working when you do.

## Fingerprint unlock

In the Android app, you can turn on fingerprint unlock.

- Your fingerprint is a **wrapper**, not a replacement. The master password is still the real key.
- The phone keeps a protected copy of the vault key, locked to your fingerprint. Your fingerprint itself never leaves the phone.
- If fingerprint unlock ever fails, your master password still works.
- Turn it off any time in Settings. Turning it off removes the protected copy.
- The web app does not offer this. A web browser cannot guard a key the way the phone can, so we do not pretend it can.

## Making a strong password

MyKey can make passwords for you.

- Let it. A made-up password is stronger than one you invent, because people invent patterns.
- Made passwords are at least 16 characters. The app shows a strength meter while you work.
- Use a different password for every service. That way, one service's leak is not every service's leak.

## Sign-in codes

Some services ask for a 6-digit code that changes every 30 seconds, on top of your password. These are called **one-time codes** (you may see the letters TOTP — that is the technical name for the same thing).

- If a service gives you a setup key for these codes, save it in the entry. MyKey then shows the current code next to the password.
- The codes stay in your vault, encrypted like everything else.
- MyKey never gives these codes to agents (see "Agents" below). Not for any entry, not ever.

## Password dates and change reminders

Passwords age. Old passwords have had more chances to leak.

- Each entry remembers the date its password was set.
- By default, MyKey suggests changing a password **180 days** after it was set. The entry then shows a "change soon" note.
- You can pick a different date for any entry, change the default in Settings, or turn the reminder off for an entry with **Never**.
- When you change a password, tell MyKey — save the new password in the entry, or tap the "changed today" action — and the clock starts again.
- A reminder is advice, not a lock. Nothing stops working when a date passes.

## Copying a password

When you copy a password, it does not stay on the clipboard.

- It clears itself after **1 minute** by default.
- You can set the wait in Settings: never less than 60 seconds, never more than 300 seconds (5 minutes).
- Locking the vault clears a copied password right away.
- The app only clears the clipboard if it still holds what the app put there. If you copy something else in the meantime, your new copy is left alone.
- On Android, copied passwords are marked **sensitive**, so the phone hides them from the clipboard preview and keeps them out of keyboard history where the phone supports that.

## Sync through your own cloud

MyKey has no server of its own. If you want the same vault on more than one device, your own cloud carries the file.

- On a computer, point MyKey at a folder that your cloud app already syncs (Drive, iCloud, OneDrive, Dropbox, or a folder on your own network). MyKey saves and loads the encrypted vault there.
- In the Android app there is no folder picker, so you move the file with your cloud app: save the vault file into your cloud app, and open it from there on the other device. The app says this plainly in Settings.
- The file that travels is always the scrambled vault. Your cloud provider cannot read it.
- If the vault changes on two devices at once, MyKey keeps both copies and tells you. It never silently overwrites one with the other.

## Backup packages

A **backup package** is one encrypted file (it ends in .mykeybak) that holds your whole vault. It is the safest way to keep a spare copy or move to a new device.

- On a device you have set up, the package opens with that device's own key.
- **Outside the app, opening a backup package needs two things**: your recovery words **and** a **backup code**. The backup code is 8 words. MyKey shows it once, at the moment you export, and never stores it. Write it down and keep it somewhere different from your recovery words.
- Words alone cannot open a new package. The code alone cannot either. That is on purpose — it takes both, so one lost paper is not the whole story. (Older packages, made before this rule, open with the words alone and are marked LEGACY so you know.)
- Treat a backup package like the vault itself: safe to store in your cloud, because it is scrambled — but do not share it.

## Pairing a cloud or export target

Before MyKey will send backups or sync files to an outside target — a cloud folder service or another device — the target must be **paired**.

- Pairing is a key-value pair you approve: the target's name on one side, its public key and what it is allowed to do on the other. (The "key" here is a long secret number, not your password.)
- A target shows you a pairing code with a short fingerprint. You compare the fingerprint, then approve. Only then is the target switched on.
- Each pairing has permissions — push (send to it), pull (load from it), export (receive backup packages) — and can have an expiry date.
- A target that is not paired gets nothing. If you revoke a pairing, future backups leave that target out.
- Only you can pair or revoke, at a moment when your vault is open. No program can pair itself.

## Agents

In the desktop app, you can give an outside program — for example an AI assistant you run — an **agent key** of its own.

- An agent key is not your master password. It is a separate key, limited to the entries you choose (by service or by tag).
- The agent can only read what its key allows. It can never see your sign-in codes, and it can never change or delete entries.
- Every use is written into a tamper-evident log you can inspect.
- You can switch a key off or revoke it any time. Revoking takes effect on the vault immediately.
- Agents are off unless you create a key. Most people never need one.

## Colours and skins

In the phone and web apps, Settings → Appearance changes how MyKey looks.

- Skins change colours only — never how anything works.
- On first use, MyKey follows your device: light or dark, your font size, and reduced motion if you use it. "Use device settings" brings that back at any time.
- Every skin is checked so text stays readable (a contrast standard called WCAG AA). If a colour cannot be read clearly, it does not ship.

## Getting passwords in and out

- **Bringing passwords in:** export a CSV file from your browser (Chrome, Edge, Firefox and others) or another password app, then import it in MyKey. The file is read on this device only — it is never uploaded. Delete the CSV file when you finish: until you open it in MyKey, it is not protected.
- **Taking passwords out:** the safe way is a backup package (above) — it stays scrambled. MyKey can also export a readable CSV file, but only after a warning and a deliberate confirmation, because anyone who gets that file can read every password in it. Guard it, and delete it as soon as you have used it.
