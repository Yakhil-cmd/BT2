# Q713: auth-profile via useFingerprintSettings 713

## Question
Can an unprivileged attacker entering through the auto-login startup path in `useFingerprintSettings` (packages/api-react/src/hooks/useFingerprintSettings.ts) control private preference values migrated from localStorage with a duplicate identifier and drive the sequence validate input -> normalize payload -> call RPC so the GUI would reuse auto-login or persisted auth state after logout/profile switch, violating the invariant that auth, fingerprint, prompt reason, route access, and pending action context must be atomic across profile changes, leading to Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass?

## Target
- File/function: `packages/api-react/src/hooks/useFingerprintSettings.ts` / `useFingerprintSettings`
- Entrypoint: auto-login startup path
- Attacker controls: private preference values migrated from localStorage; with a duplicate identifier
- Exploit idea: reuse auto-login or persisted auth state after logout/profile switch
- Invariant to test: auth, fingerprint, prompt reason, route access, and pending action context must be atomic across profile changes
- Expected Immunefi impact: Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
