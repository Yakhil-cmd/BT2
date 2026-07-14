# Q2407: auth-profile via selectWalletRpcPreferences 2407

## Question
Can an unprivileged attacker entering through the persisted preference reload in `selectWalletRpcPreferences` (packages/api-react/src/slices/walletRpcPreferences.ts) control dismiss/cancel sequence during pending RPC action with a cached permission entry and drive the sequence import -> parse -> preview -> submit so the GUI would leave modal approval state alive across account changes, violating the invariant that auth, fingerprint, prompt reason, route access, and pending action context must be atomic across profile changes, leading to Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass?

## Target
- File/function: `packages/api-react/src/slices/walletRpcPreferences.ts` / `selectWalletRpcPreferences`
- Entrypoint: persisted preference reload
- Attacker controls: dismiss/cancel sequence during pending RPC action; with a cached permission entry
- Exploit idea: leave modal approval state alive across account changes
- Invariant to test: auth, fingerprint, prompt reason, route access, and pending action context must be atomic across profile changes
- Expected Immunefi impact: Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
