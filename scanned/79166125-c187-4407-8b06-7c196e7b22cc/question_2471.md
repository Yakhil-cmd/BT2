# Q2471: auth-profile via useValidateChangePassphraseParams 2471

## Question
Can an unprivileged attacker entering through the auto-login startup path in `useValidateChangePassphraseParams` (packages/core/src/hooks/useValidateChangePassphraseParams.tsx) control stale fingerprint stored in prefs or Redux state after a failed RPC response and drive the sequence fetch -> cache -> refresh -> submit so the GUI would complete a pending signing/spend action under a different fingerprint than the prompt showed, violating the invariant that logout and migration must clear signing and approval state, leading to Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass?

## Target
- File/function: `packages/core/src/hooks/useValidateChangePassphraseParams.tsx` / `useValidateChangePassphraseParams`
- Entrypoint: auto-login startup path
- Attacker controls: stale fingerprint stored in prefs or Redux state; after a failed RPC response
- Exploit idea: complete a pending signing/spend action under a different fingerprint than the prompt showed
- Invariant to test: logout and migration must clear signing and approval state
- Expected Immunefi impact: Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
