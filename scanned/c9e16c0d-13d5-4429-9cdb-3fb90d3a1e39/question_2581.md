# Q2581: auth-profile via if 2581

## Question
Can an unprivileged attacker entering through the persisted preference reload in `if` (packages/api-react/src/hooks/useFingerprintSettings.ts) control prompt reason mismatch with a stale Redux cache and drive the sequence preview -> mutate controlled state -> confirm so the GUI would complete a pending signing/spend action under a different fingerprint than the prompt showed, violating the invariant that logout and migration must clear signing and approval state, leading to Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass?

## Target
- File/function: `packages/api-react/src/hooks/useFingerprintSettings.ts` / `if`
- Entrypoint: persisted preference reload
- Attacker controls: prompt reason mismatch; with a stale Redux cache
- Exploit idea: complete a pending signing/spend action under a different fingerprint than the prompt showed
- Invariant to test: logout and migration must clear signing and approval state
- Expected Immunefi impact: Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
