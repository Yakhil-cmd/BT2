# Q601: auth-profile via useAuth 601

## Question
Can an unprivileged attacker entering through the persisted preference reload in `useAuth` (packages/core/src/hooks/useAuth.ts) control prompt reason mismatch with hidden Unicode characters and drive the sequence fetch -> cache -> refresh -> submit so the GUI would leave modal approval state alive across account changes, violating the invariant that persisted preferences must not grant authority without current authentication, leading to Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass?

## Target
- File/function: `packages/core/src/hooks/useAuth.ts` / `useAuth`
- Entrypoint: persisted preference reload
- Attacker controls: prompt reason mismatch; with hidden Unicode characters
- Exploit idea: leave modal approval state alive across account changes
- Invariant to test: persisted preferences must not grant authority without current authentication
- Expected Immunefi impact: Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
