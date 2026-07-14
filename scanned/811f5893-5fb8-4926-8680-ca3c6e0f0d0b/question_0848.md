# Q848: auth-profile via useKeyringMigrationPrompt 848

## Question
Can an unprivileged attacker entering through the passphrase prompt workflow in `useKeyringMigrationPrompt` (packages/core/src/hooks/useKeyringMigrationPrompt.tsx) control prompt reason mismatch after a network switch and drive the sequence preview -> mutate controlled state -> confirm so the GUI would skip a required passphrase prompt because prompt reason or route guard becomes stale, violating the invariant that persisted preferences must not grant authority without current authentication, leading to Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass?

## Target
- File/function: `packages/core/src/hooks/useKeyringMigrationPrompt.tsx` / `useKeyringMigrationPrompt`
- Entrypoint: passphrase prompt workflow
- Attacker controls: prompt reason mismatch; after a network switch
- Exploit idea: skip a required passphrase prompt because prompt reason or route guard becomes stale
- Invariant to test: persisted preferences must not grant authority without current authentication
- Expected Immunefi impact: Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
