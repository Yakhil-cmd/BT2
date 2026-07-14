# Q2737: auth-profile via handleKeyDown 2737

## Question
Can an unprivileged attacker entering through the passphrase prompt workflow in `handleKeyDown` (packages/gui/src/components/app/AppPassPrompt.tsx) control rapid logout/login/profile switch timing with case-normalized identifiers and drive the sequence fetch -> cache -> refresh -> submit so the GUI would reuse auto-login or persisted auth state after logout/profile switch, violating the invariant that logout and migration must clear signing and approval state, leading to Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass?

## Target
- File/function: `packages/gui/src/components/app/AppPassPrompt.tsx` / `handleKeyDown`
- Entrypoint: passphrase prompt workflow
- Attacker controls: rapid logout/login/profile switch timing; with case-normalized identifiers
- Exploit idea: reuse auto-login or persisted auth state after logout/profile switch
- Invariant to test: logout and migration must clear signing and approval state
- Expected Immunefi impact: Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
