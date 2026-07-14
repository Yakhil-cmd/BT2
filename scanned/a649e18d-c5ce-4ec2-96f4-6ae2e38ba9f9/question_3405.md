# Q3405: auth-profile via validateChangePassphraseParams 3405

## Question
Can an unprivileged attacker entering through the passphrase prompt workflow in `validateChangePassphraseParams` (packages/core/src/hooks/useValidateChangePassphraseParams.tsx) control private preference values migrated from localStorage after a network switch and drive the sequence import -> parse -> preview -> submit so the GUI would reuse auto-login or persisted auth state after logout/profile switch, violating the invariant that auth, fingerprint, prompt reason, route access, and pending action context must be atomic across profile changes, leading to Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass?

## Target
- File/function: `packages/core/src/hooks/useValidateChangePassphraseParams.tsx` / `validateChangePassphraseParams`
- Entrypoint: passphrase prompt workflow
- Attacker controls: private preference values migrated from localStorage; after a network switch
- Exploit idea: reuse auto-login or persisted auth state after logout/profile switch
- Invariant to test: auth, fingerprint, prompt reason, route access, and pending action context must be atomic across profile changes
- Expected Immunefi impact: Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
