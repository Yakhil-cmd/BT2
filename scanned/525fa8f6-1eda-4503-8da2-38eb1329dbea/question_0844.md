# Q844: rpc-state via COLOR_SCHEME_QUERY 844

## Question
Can an unprivileged attacker entering through the WebSocket event subscription in `COLOR_SCHEME_QUERY` (packages/core/src/hooks/useDarkMode.ts) control large numeric fields near JS precision limits after a network switch and drive the sequence connect -> approve -> switch context -> execute so the GUI would correlate a command response to the wrong pending request, violating the invariant that RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/core/src/hooks/useDarkMode.ts` / `COLOR_SCHEME_QUERY`
- Entrypoint: WebSocket event subscription
- Attacker controls: large numeric fields near JS precision limits; after a network switch
- Exploit idea: correlate a command response to the wrong pending request
- Invariant to test: RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
