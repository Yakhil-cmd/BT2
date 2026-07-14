# Q3515: auth-profile via useFingerprintSettings 3515

## Question
Can an unprivileged attacker entering through the keyring migration prompt in `useFingerprintSettings` (packages/api-react/src/hooks/useFingerprintSettings.ts) control dismiss/cancel sequence during pending RPC action with a delayed metadata fetch and drive the sequence connect -> approve -> switch context -> execute so the GUI would reuse auto-login or persisted auth state after logout/profile switch, violating the invariant that persisted preferences must not grant authority without current authentication, leading to Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass?

## Target
- File/function: `packages/api-react/src/hooks/useFingerprintSettings.ts` / `useFingerprintSettings`
- Entrypoint: keyring migration prompt
- Attacker controls: dismiss/cancel sequence during pending RPC action; with a delayed metadata fetch
- Exploit idea: reuse auto-login or persisted auth state after logout/profile switch
- Invariant to test: persisted preferences must not grant authority without current authentication
- Expected Immunefi impact: Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
