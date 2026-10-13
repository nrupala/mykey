<!-- Canonical in-app FAQ for MyKey. This file is the single
     source: the desktop app shows it from the Help menu, and the
     phone / web app carries a byte-for-byte copy in src/content/.
     Edit here first, then re-mirror. Plain words on purpose. -->

# Common questions

## I forgot my master password. What now?

Use your recovery words. On the locked screen, choose "Use my recovery phrase instead", type the 12 words in order, and the vault opens. Then set a new master password in Settings.

If you have neither the password nor the words, the vault cannot be opened — by anyone, including us. That is the honest cost of a vault nobody else can break into. It is why the words matter.

## I lost my phone. How do I get my passwords back?

On your new device, install MyKey, then either:

- open your vault file (if a copy is in your cloud) with your master password, or
- restore from a backup package. Outside the app that takes your recovery words **and** the backup code you wrote down at export.

Then, in the desktop app, revoke the lost phone's device entry so new backup packages no longer include it. Packages you exported before the loss can still be opened by the lost phone's key — no product can undo that — so keep your recovery words and backup code safe and change important passwords if the phone held them unlocked.

## Does MyKey work without internet?

Yes, fully. There is no account, no sign-in, and no server. Creating a vault, opening it, syncing through a folder, making and restoring backups — none of it needs a connection. If you use a cloud folder, your cloud app moves the file when it has a connection; MyKey itself never connects anywhere.

## Where is my data stored?

On your device, as one encrypted vault file. If you sync, a copy of that same scrambled file sits in the cloud folder you chose. If you export a backup package, it is wherever you put it. MyKey stores nothing anywhere else.

## Can the company read my passwords?

No. Your vault is scrambled on your device with a key made from your master password, and that key never leaves your device. We have no copy of your password, your recovery words, or your vault. This is sometimes called "zero-knowledge": there is nothing for us to read, hand over, or leak.

## What happens when I copy a password?

It goes to the clipboard so you can paste it, and then it clears itself — after 1 minute by default. You can change the wait in Settings, from 60 seconds up to 300 seconds (5 minutes). If you lock the vault, it clears right away. If you copy something else first, the app leaves your new copy alone and clears nothing.

## Why does a password say "change soon"?

Each entry remembers when its password was set. The default reminder is 180 days. When the date passes, the entry shows "change soon". It is advice, not a block — the password still works everywhere. Change the password at the service, save the new one in MyKey, and the reminder resets. You can change the reminder period, set a date per entry, or choose Never — see Settings.

## How do I bring my passwords from Chrome or Firefox?

- In the browser, export your passwords to a CSV file. (In Chrome: Settings → Autofill → Password Manager → Settings → Export. In Firefox: Settings → Privacy & Security → Saved Logins → the menu → Export Logins.)
- In MyKey, choose the import option and pick that file. Chrome-family and Firefox files are recognised on their own; other files let you match the columns by hand.
- MyKey shows you what it found before anything is imported, and asks what to do about duplicates.
- When the import is done, delete the CSV file. Until it is inside MyKey, it is a readable list of your passwords.

## How do I get my passwords out of MyKey?

Two ways:

- **A backup package** is the safe way. It is one encrypted file. On a device you set up, it opens with the device key; elsewhere it needs your recovery words plus the backup code from export.
- **A CSV file** is the readable way — for moving into another app. MyKey warns you and asks you to confirm, because anyone holding that file can read every password. Use it, then delete it.

## What if someone steals my vault file?

They have a scrambled file they cannot read. Opening it needs your master password or your recovery words, and guessing is slowed down on purpose by the way the key is made. A long master password is what protects you here — that is why MyKey asks for at least 12 characters.

## My fingerprint stopped working. What do I do?

Use your master password — it always works. Then check that your fingerprint is still set up on the phone. If you removed and re-added fingerprints, turn fingerprint unlock off in Settings and turn it on again so it matches the phone again.

## What are the recovery words for, exactly?

They are a spare key, written as 12 words. They open your vault if you forget the master password, and together with the backup code they open backup packages on a new device. Keep them on paper, somewhere safe, and never share them or type them into a website. You can replace them in Settings — the old set stops working at once.

## Can I use MyKey on more than one device?

Yes. Keep the same vault on your devices through your own cloud folder, or carry the vault file or a backup package across by hand. Each device opens the vault with your master password. There is no limit and no account to sign into.

## What is an agent key? Do I need one?

Probably not. In the desktop app you can give a program you trust — like an AI assistant — its own limited key, so it can read only the entries you pick, never your sign-in codes, and never with your master password. You create it, you can revoke it any time, and every use is logged. If you never use such a program, ignore agents completely; they are off by default.
