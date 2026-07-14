# Q2711: rpc-state via useCurrencyCode 2711

## Question
Can an unprivileged attacker entering through the RTK query cache update in `useCurrencyCode` (packages/core/src/hooks/useCurrencyCode.ts) control subscription event for a different wallet/fingerprint with a stale Redux cache and drive the sequence fetch -> cache -> refresh -> submit so the GUI would mis-handle precision for mojos, royalties, or fees in state, violating the invariant that RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/core/src/hooks/useCurrencyCode.ts` / `useCurrencyCode`
- Entrypoint: RTK query cache update
- Attacker controls: subscription event for a different wallet/fingerprint; with a stale Redux cache
- Exploit idea: mis-handle precision for mojos, royalties, or fees in state
- Invariant to test: RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
