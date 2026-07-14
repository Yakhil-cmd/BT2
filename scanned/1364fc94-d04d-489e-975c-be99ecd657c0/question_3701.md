# Q3701: auth-profile via useEnableAutoLogin 3701

## Question
Can an unprivileged attacker entering through the persisted preference reload in `useEnableAutoLogin` (packages/gui/src/hooks/useEnableAutoLogin.ts) control stale fingerprint stored in prefs or Redux state through a batch of rapid user-accessible actions and drive the sequence connect -> approve -> switch context -> execute so the GUI would leave modal approval state alive across account changes, violating the invariant that auth, fingerprint, prompt reason, route access, and pending action context must be atomic across profile changes, leading to Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass?

## Target
- File/function: `packages/gui/src/hooks/useEnableAutoLogin.ts` / `useEnableAutoLogin`
- Entrypoint: persisted preference reload
- Attacker controls: stale fingerprint stored in prefs or Redux state; through a batch of rapid user-accessible actions
- Exploit idea: leave modal approval state alive across account changes
- Invariant to test: auth, fingerprint, prompt reason, route access, and pending action context must be atomic across profile changes
- Expected Immunefi impact: Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
