# Signup automation for Hermes

This Hermes plugin creates website credentials without showing passwords or authenticator seeds to the model. It targets Linux and macOS (`fcntl` locks are required) and stores new logins in a dedicated Bitwarden Secrets Manager project and in the local encrypted Hermes vault. The local vault supplies opaque `vault_...` handles for later fills. Bitwarden Password Manager and Bitwarden Secrets Manager are different products: a locked personal Password Manager CLI vault does not block this plugin's machine-account route.

## Install

1. Install the plugin from Git with `hermes plugins install <owner>/<private-repo>` using authorized Git credentials, or copy the directory into the active profile's `$HERMES_HOME/plugins/signup-automation/` (normally `~/.hermes/plugins/signup-automation/`). Keep all Python files, `plugin.yaml`, and `settings.json` together. `hermes plugins install` installs manifest dependencies unless `--no-deps` is set; a manually copied directory does not install them, so install the four packages declared under `python_dependencies` into Hermes's Python environment yourself. Reload the plugins or restart the gateway to activate code changes; a new session picks up current tool schemas.
2. Create a Bitwarden Secrets Manager organization, a project for website accounts, and a machine account with read/write access to that project. Put the organization and project UUIDs in a local `settings.local.json` copied from `settings.json`. The checked-in template deliberately leaves both UUIDs blank. `settings.local.json` is gitignored.
3. Configure `BWS_ACCESS_TOKEN` and the agent mailbox's `EMAIL_ADDRESS` in the active Hermes secret environment (`$HERMES_HOME/.env`). For emailed codes also configure `EMAIL_IMAP_HOST`, `EMAIL_IMAP_PORT`, and `EMAIL_PASSWORD`. The verifier cryptographically checks an aligned sender-domain DKIM signature and refuses unsigned mail, rather than trusting a sender-controlled `Authentication-Results` header. It needs DNS access to verify the sender's public key. Do not put access tokens or mailbox passwords in `settings.json`, CLI arguments, or this repository.
4. In a fresh Hermes session, discover `signup_automation` with `tool_search`, then use `tool_describe` for the needed tools. Plugin tools can be on demand and absent from the initial tool list. The `pre_llm_call` hook provides the same credential-route guidance for signup requests.

The plugin uses the current supervised Hermes browser page. Secret fills through Camofox require the browser service to be bound to localhost; remote Camofox evaluations are refused. An exact origin match is required on every fill. The active browser and a Bitwarden machine account with project access are prerequisites; a personal Bitwarden Password Manager unlock is not.

## New website account

1. Open the site's email/password registration page. Call `signup_prepare_login` there. It uses the configured agent email unless an email is supplied and returns an opaque login handle. It refuses to create a second saved login for that email and origin. Automatic emailed-code retrieval works only when the signup email equals the configured agent inbox (`EMAIL_ADDRESS`); another email may be used for registration, but this plugin cannot fetch its verification mail.
2. Call `signup_fill_registration` with the handle; then submit the site's registration form with the ordinary browser tool. Filling does not submit or prove the account exists.
3. If the site offers authenticator enrollment, call `signup_capture_totp` with that handle on the QR/setup page. It saves the key in both stores and returns only metadata. Call `signup_fill_totp`, submit the site's confirmation form, and check the site's success state. A saved key or filled code alone does not prove enrollment. If the site regenerates its QR after a failed attempt, capture the current QR again before filling a new code.
4. Before requesting an emailed code, call `signup_arm_email_challenge` on the site's email entry page. If `signup_prepare_login` just succeeded in this gateway session, it already armed that signup origin and address, but arming again immediately before submission is safe. On email-first signup omit the handle; the page must show the configured agent email (visible text or email input). Request the code only after arming. On the code form, call `signup_fill_email_code` with the handle if available, or omit it for email-first signup. It fills a verified code without returning it. If the challenge was not armed before the message arrived, arm it on the current site, request a **new** code, and then retry. Submit and verify the site's completion state.
5. Complete any CAPTCHA, passkey, SMS, or identity step through the appropriate authorized workflow; do not claim those steps are automatic.

For a brand-new account, do not request a pre-existing login or choose Google OAuth merely because the personal Bitwarden vault is locked. Reuse a saved handle rather than generating another password if registration has already started.

## Existing saved account

Open the site's sign-in page and call `signup_fill_login` with the saved handle. Submit the form; if asked for an authenticator code, call `signup_fill_totp`, submit, and verify a signed-in page. For an emailed code, call `signup_arm_email_challenge` with the handle **before** requesting the mail, then `signup_fill_email_code`. If the site already sent it, arm and request a new one. The tools do not submit forms. A login handle is bound to its original website origin; the plugin refuses cross-origin fills.

## Storage and failure behavior

- `settings.local.json` is local-only configuration. The mapping file `$HERMES_HOME/signup_bitwarden_ids.json` links local handles to Bitwarden secret IDs and is written with mode 0600. Never commit either file, `$HERMES_HOME/.env`, captured browser data, or generated credentials.
- `signup_prepare_login` writes to Bitwarden Secrets Manager first, then the Hermes vault and the local ID mapping. If the initial remote create times out, its result is unknown and the tool returns `manual_reconciliation_required`; check for an unlinked remote copy before retrying. If a later local step fails, it attempts to remove the Bitwarden copy before cleaning up locally. If cleanup fails, it also returns `manual_reconciliation_required` with opaque IDs. No website account has been submitted at that point.
- `signup_capture_totp` saves to Bitwarden before updating the local record. If the remote update returns an ambiguous failure, it reads the remote record and restores the previous key when necessary; if its state cannot be confirmed, it returns `manual_reconciliation_required`. If the local write fails, it attempts to restore the prior Bitwarden key and verifies the local record. Stop and investigate rather than claiming authenticator enrollment succeeded.
- `signup_fill_email_code` requires an arm marker for this gateway task, origin, and mailbox; arming waits until the next whole second before returning, so IMAP's second-resolution `INTERNALDATE` cannot discard a new code requested immediately afterward. It accepts only mail delivered after arming and within 90 minutes, then consumes the marker after a successful fill; a new request requires re-arming. It checks the current site's sender domain, target mailbox in To, and a cryptographically valid aligned DKIM signature that covers From, To, Subject, and the full body. Subject-only brand matches, unsigned mail, and forged authentication headers are rejected. Multiple distinct codes after arming are refused; re-arm and request a new code. A gateway restart clears arm markers. Timing and sender checks cannot cryptographically prove a generic code belongs to one specific browser challenge if two same-site challenges overlap, so do not run concurrent challenges for one account.
- Passwords and OTPs are filled inside a supervised browser operation and registered for redaction. Tool results contain status and handles, not secret values. Do not print secret configuration or inspect filled form values in ordinary browser tools.

## Verify

Run the offline checks from this directory:

```sh
python3 -m unittest discover -s tests -v
python3 -m compileall -q __init__.py signup.py bitwarden_store.py
```

The offline suite executes browser-side JavaScript with Node.js; install Node.js to run those regression tests.

Then, in a fresh Hermes session, verify tool discovery and a disposable site's registration and later login, including any actual code challenge. The offline suite cannot establish live Bitwarden permissions, mail delivery, browser compatibility, or that a third-party website activated an account. If `signup_prepare_login` cannot identify the registration form, check that the supervised browser is on the actual email/password registration page and that it has a password field; do not generate or type a substitute password manually.
