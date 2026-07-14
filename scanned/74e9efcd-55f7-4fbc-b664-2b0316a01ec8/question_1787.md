# Q1787: auth-profile via setValue 1787

## Question
Can an unprivileged attacker entering through the keyring migration prompt in `setValue` (packages/core/src/hooks/usePersistState.ts) control dismiss/cancel sequence during pending RPC action through a batch of rapid user-accessible actions and drive the sequence open notification -> resolve details -> execute so the GUI would leave modal approval state alive across account changes, violating the invariant that persisted preferences must not grant authority without current authentication, leading to Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass?

## Target
- File/function: `packages/core/src/hooks/usePersistState.ts` / `setValue`
- Entrypoint: keyring migration prompt
- Attacker controls: dismiss/cancel sequence during pending RPC action; through a batch of rapid user-accessible actions
- Exploit idea: leave modal approval state alive across account changes
- Invariant to test: persisted preferences must not grant authority without current authentication
- Expected Immunefi impact: Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
