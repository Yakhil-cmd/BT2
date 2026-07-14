# Q3403: auth-profile via if 3403

## Question
Can an unprivileged attacker entering through the auto-login startup path in `if` (packages/core/src/hooks/useAuth.ts) control stale fingerprint stored in prefs or Redux state with precision-boundary values and drive the sequence fetch -> cache -> refresh -> submit so the GUI would leave modal approval state alive across account changes, violating the invariant that persisted preferences must not grant authority without current authentication, leading to Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass?

## Target
- File/function: `packages/core/src/hooks/useAuth.ts` / `if`
- Entrypoint: auto-login startup path
- Attacker controls: stale fingerprint stored in prefs or Redux state; with precision-boundary values
- Exploit idea: leave modal approval state alive across account changes
- Invariant to test: persisted preferences must not grant authority without current authentication
- Expected Immunefi impact: Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
