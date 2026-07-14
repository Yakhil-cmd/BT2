# Q1498: auth-profile via PassphrasePromptReason 1498

## Question
Can an unprivileged attacker entering through the persisted preference reload in `PassphrasePromptReason` (packages/api/src/constants/PassphrasePromptReason.ts) control stale fingerprint stored in prefs or Redux state through a batch of rapid user-accessible actions and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would reuse auto-login or persisted auth state after logout/profile switch, violating the invariant that logout and migration must clear signing and approval state, leading to Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass?

## Target
- File/function: `packages/api/src/constants/PassphrasePromptReason.ts` / `PassphrasePromptReason`
- Entrypoint: persisted preference reload
- Attacker controls: stale fingerprint stored in prefs or Redux state; through a batch of rapid user-accessible actions
- Exploit idea: reuse auto-login or persisted auth state after logout/profile switch
- Invariant to test: logout and migration must clear signing and approval state
- Expected Immunefi impact: Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
