# Q2748: auth-profile via handleClick 2748

## Question
Can an unprivileged attacker entering through the keyring migration prompt in `handleClick` (packages/gui/src/components/settings/ProfileAdd.tsx) control stale fingerprint stored in prefs or Redux state through a batch of rapid user-accessible actions and drive the sequence connect -> approve -> switch context -> execute so the GUI would complete a pending signing/spend action under a different fingerprint than the prompt showed, violating the invariant that logout and migration must clear signing and approval state, leading to Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass?

## Target
- File/function: `packages/gui/src/components/settings/ProfileAdd.tsx` / `handleClick`
- Entrypoint: keyring migration prompt
- Attacker controls: stale fingerprint stored in prefs or Redux state; through a batch of rapid user-accessible actions
- Exploit idea: complete a pending signing/spend action under a different fingerprint than the prompt showed
- Invariant to test: logout and migration must clear signing and approval state
- Expected Immunefi impact: Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
