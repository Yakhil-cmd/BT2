# Q2634: auth-profile via KeyringStatus 2634

## Question
Can an unprivileged attacker entering through the keyring migration prompt in `KeyringStatus` (packages/api/src/@types/KeyringStatus.ts) control rapid logout/login/profile switch timing with precision-boundary values and drive the sequence open notification -> resolve details -> execute so the GUI would reuse auto-login or persisted auth state after logout/profile switch, violating the invariant that persisted preferences must not grant authority without current authentication, leading to Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass?

## Target
- File/function: `packages/api/src/@types/KeyringStatus.ts` / `KeyringStatus`
- Entrypoint: keyring migration prompt
- Attacker controls: rapid logout/login/profile switch timing; with precision-boundary values
- Exploit idea: reuse auto-login or persisted auth state after logout/profile switch
- Invariant to test: persisted preferences must not grant authority without current authentication
- Expected Immunefi impact: Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
