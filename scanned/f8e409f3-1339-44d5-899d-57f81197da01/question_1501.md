# Q1501: rpc-state via ServiceName 1501

## Question
Can an unprivileged attacker entering through the WebSocket event subscription in `ServiceName` (packages/api/src/constants/ServiceName.ts) control out-of-order event and query responses after a profile switch and drive the sequence validate input -> normalize payload -> call RPC so the GUI would correlate a command response to the wrong pending request, violating the invariant that RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/api/src/constants/ServiceName.ts` / `ServiceName`
- Entrypoint: WebSocket event subscription
- Attacker controls: out-of-order event and query responses; after a profile switch
- Exploit idea: correlate a command response to the wrong pending request
- Invariant to test: RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
