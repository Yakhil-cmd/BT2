# Q2511: auth-profile via readPreferences 2511

## Question
Can an unprivileged attacker entering through the keyring migration prompt in `readPreferences` (packages/gui/src/electron/utils/privatePreferences.ts) control stale fingerprint stored in prefs or Redux state with case-normalized identifiers and drive the sequence load persisted state -> render approval -> execute command so the GUI would complete a pending signing/spend action under a different fingerprint than the prompt showed, violating the invariant that logout and migration must clear signing and approval state, leading to Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass?

## Target
- File/function: `packages/gui/src/electron/utils/privatePreferences.ts` / `readPreferences`
- Entrypoint: keyring migration prompt
- Attacker controls: stale fingerprint stored in prefs or Redux state; with case-normalized identifiers
- Exploit idea: complete a pending signing/spend action under a different fingerprint than the prompt showed
- Invariant to test: logout and migration must clear signing and approval state
- Expected Immunefi impact: Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
