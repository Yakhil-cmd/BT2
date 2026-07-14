# Q3514: auth-profile via useCurrentFingerprintSettings 3514

## Question
Can an unprivileged attacker entering through the persisted preference reload in `useCurrentFingerprintSettings` (packages/api-react/src/hooks/useCurrentFingerprintSettings.ts) control rapid logout/login/profile switch timing through a batch of rapid user-accessible actions and drive the sequence download or render content -> trigger linked wallet action so the GUI would migrate untrusted localStorage values into security-sensitive prefs, violating the invariant that persisted preferences must not grant authority without current authentication, leading to Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass?

## Target
- File/function: `packages/api-react/src/hooks/useCurrentFingerprintSettings.ts` / `useCurrentFingerprintSettings`
- Entrypoint: persisted preference reload
- Attacker controls: rapid logout/login/profile switch timing; through a batch of rapid user-accessible actions
- Exploit idea: migrate untrusted localStorage values into security-sensitive prefs
- Invariant to test: persisted preferences must not grant authority without current authentication
- Expected Immunefi impact: Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
