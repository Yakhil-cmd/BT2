# Q3340: rpc-state via normalizedAuthorizedProviders 3340

## Question
Can an unprivileged attacker entering through the daemon RPC response handling in `normalizedAuthorizedProviders` (packages/api-react/src/services/wallet.ts) control RPC error payload shaped like success with hidden Unicode characters and drive the sequence open notification -> resolve details -> execute so the GUI would display one balance/asset state while executing with another, violating the invariant that error states must not be treated as successful authorization, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/api-react/src/services/wallet.ts` / `normalizedAuthorizedProviders`
- Entrypoint: daemon RPC response handling
- Attacker controls: RPC error payload shaped like success; with hidden Unicode characters
- Exploit idea: display one balance/asset state while executing with another
- Invariant to test: error states must not be treated as successful authorization
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
