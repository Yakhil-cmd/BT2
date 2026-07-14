# Q2580: auth-profile via useCurrentFingerprintSettings 2580

## Question
Can an unprivileged attacker entering through the passphrase prompt workflow in `useCurrentFingerprintSettings` (packages/api-react/src/hooks/useCurrentFingerprintSettings.ts) control dismiss/cancel sequence during pending RPC action with precision-boundary values and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would reuse auto-login or persisted auth state after logout/profile switch, violating the invariant that logout and migration must clear signing and approval state, leading to Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass?

## Target
- File/function: `packages/api-react/src/hooks/useCurrentFingerprintSettings.ts` / `useCurrentFingerprintSettings`
- Entrypoint: passphrase prompt workflow
- Attacker controls: dismiss/cancel sequence during pending RPC action; with precision-boundary values
- Exploit idea: reuse auto-login or persisted auth state after logout/profile switch
- Invariant to test: logout and migration must clear signing and approval state
- Expected Immunefi impact: Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
