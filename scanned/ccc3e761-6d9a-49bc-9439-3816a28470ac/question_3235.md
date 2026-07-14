# Q3235: auth-profile via savePrefs 3235

## Question
Can an unprivileged attacker entering through the keyring migration prompt in `savePrefs` (packages/gui/src/electron/prefs.ts) control prompt reason mismatch with hidden Unicode characters and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would complete a pending signing/spend action under a different fingerprint than the prompt showed, violating the invariant that auth, fingerprint, prompt reason, route access, and pending action context must be atomic across profile changes, leading to Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass?

## Target
- File/function: `packages/gui/src/electron/prefs.ts` / `savePrefs`
- Entrypoint: keyring migration prompt
- Attacker controls: prompt reason mismatch; with hidden Unicode characters
- Exploit idea: complete a pending signing/spend action under a different fingerprint than the prompt showed
- Invariant to test: auth, fingerprint, prompt reason, route access, and pending action context must be atomic across profile changes
- Expected Immunefi impact: Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
