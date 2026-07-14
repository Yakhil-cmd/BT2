# Q2716: auth-profile via useKeyringMigrationPrompt 2716

## Question
Can an unprivileged attacker entering through the keyring migration prompt in `useKeyringMigrationPrompt` (packages/core/src/hooks/useKeyringMigrationPrompt.tsx) control rapid logout/login/profile switch timing after canceling and reopening the dialog and drive the sequence fetch -> cache -> refresh -> submit so the GUI would reuse auto-login or persisted auth state after logout/profile switch, violating the invariant that logout and migration must clear signing and approval state, leading to Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass?

## Target
- File/function: `packages/core/src/hooks/useKeyringMigrationPrompt.tsx` / `useKeyringMigrationPrompt`
- Entrypoint: keyring migration prompt
- Attacker controls: rapid logout/login/profile switch timing; after canceling and reopening the dialog
- Exploit idea: reuse auto-login or persisted auth state after logout/profile switch
- Invariant to test: logout and migration must clear signing and approval state
- Expected Immunefi impact: Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
