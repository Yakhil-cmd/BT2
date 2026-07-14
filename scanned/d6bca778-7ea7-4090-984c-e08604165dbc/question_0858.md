# Q858: rpc-state via useSkipMigration 858

## Question
Can an unprivileged attacker entering through the daemon RPC response handling in `useSkipMigration` (packages/core/src/hooks/useSkipMigration.ts) control out-of-order event and query responses with hidden Unicode characters and drive the sequence import -> parse -> preview -> submit so the GUI would mis-handle precision for mojos, royalties, or fees in state, violating the invariant that RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/core/src/hooks/useSkipMigration.ts` / `useSkipMigration`
- Entrypoint: daemon RPC response handling
- Attacker controls: out-of-order event and query responses; with hidden Unicode characters
- Exploit idea: mis-handle precision for mojos, royalties, or fees in state
- Invariant to test: RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
