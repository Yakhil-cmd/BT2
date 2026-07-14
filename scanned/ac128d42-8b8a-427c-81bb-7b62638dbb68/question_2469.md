# Q2469: auth-profile via useAuth 2469

## Question
Can an unprivileged attacker entering through the profile/fingerprint switch in `useAuth` (packages/core/src/hooks/useAuth.ts) control private preference values migrated from localStorage after a network switch and drive the sequence validate input -> normalize payload -> call RPC so the GUI would skip a required passphrase prompt because prompt reason or route guard becomes stale, violating the invariant that persisted preferences must not grant authority without current authentication, leading to Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass?

## Target
- File/function: `packages/core/src/hooks/useAuth.ts` / `useAuth`
- Entrypoint: profile/fingerprint switch
- Attacker controls: private preference values migrated from localStorage; after a network switch
- Exploit idea: skip a required passphrase prompt because prompt reason or route guard becomes stale
- Invariant to test: persisted preferences must not grant authority without current authentication
- Expected Immunefi impact: Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
