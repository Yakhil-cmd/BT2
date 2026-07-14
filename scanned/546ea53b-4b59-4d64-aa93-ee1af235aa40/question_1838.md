# Q1838: rpc-state via if 1838

## Question
Can an unprivileged attacker entering through the WebSocket event subscription in `if` (packages/gui/src/hooks/useIsMainnet.tsx) control large numeric fields near JS precision limits with a redirected remote resource and drive the sequence fetch -> cache -> refresh -> submit so the GUI would correlate a command response to the wrong pending request, violating the invariant that RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/gui/src/hooks/useIsMainnet.tsx` / `if`
- Entrypoint: WebSocket event subscription
- Attacker controls: large numeric fields near JS precision limits; with a redirected remote resource
- Exploit idea: correlate a command response to the wrong pending request
- Invariant to test: RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
