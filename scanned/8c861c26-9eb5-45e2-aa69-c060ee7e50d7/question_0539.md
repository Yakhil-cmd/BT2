# Q539: auth-profile via loadFromStorage 539

## Question
Can an unprivileged attacker entering through the auto-login startup path in `loadFromStorage` (packages/api-react/src/slices/walletRpcPreferences.ts) control private preference values migrated from localStorage with a delayed metadata fetch and drive the sequence validate input -> normalize payload -> call RPC so the GUI would complete a pending signing/spend action under a different fingerprint than the prompt showed, violating the invariant that logout and migration must clear signing and approval state, leading to Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass?

## Target
- File/function: `packages/api-react/src/slices/walletRpcPreferences.ts` / `loadFromStorage`
- Entrypoint: auto-login startup path
- Attacker controls: private preference values migrated from localStorage; with a delayed metadata fetch
- Exploit idea: complete a pending signing/spend action under a different fingerprint than the prompt showed
- Invariant to test: logout and migration must clear signing and approval state
- Expected Immunefi impact: Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
