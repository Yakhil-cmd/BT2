# Q3234: auth-profile via savePrefs 3234

## Question
Can an unprivileged attacker entering through the profile/fingerprint switch in `savePrefs` (packages/gui/src/electron/prefs.ts) control stale fingerprint stored in prefs or Redux state with precision-boundary values and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would complete a pending signing/spend action under a different fingerprint than the prompt showed, violating the invariant that persisted preferences must not grant authority without current authentication, leading to Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass?

## Target
- File/function: `packages/gui/src/electron/prefs.ts` / `savePrefs`
- Entrypoint: profile/fingerprint switch
- Attacker controls: stale fingerprint stored in prefs or Redux state; with precision-boundary values
- Exploit idea: complete a pending signing/spend action under a different fingerprint than the prompt showed
- Invariant to test: persisted preferences must not grant authority without current authentication
- Expected Immunefi impact: Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
