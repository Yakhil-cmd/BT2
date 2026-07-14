# Q347: rpc-state via getIsIncomingClawbackTransaction 347

## Question
Can an unprivileged attacker entering through the daemon RPC response handling in `getIsIncomingClawbackTransaction` (packages/wallets/src/components/WalletHistory.tsx) control RPC error payload shaped like success with a stale Redux cache and drive the sequence load persisted state -> render approval -> execute command so the GUI would display one balance/asset state while executing with another, violating the invariant that RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/wallets/src/components/WalletHistory.tsx` / `getIsIncomingClawbackTransaction`
- Entrypoint: daemon RPC response handling
- Attacker controls: RPC error payload shaped like success; with a stale Redux cache
- Exploit idea: display one balance/asset state while executing with another
- Invariant to test: RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
