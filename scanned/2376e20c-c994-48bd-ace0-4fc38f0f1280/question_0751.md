# Q751: rpc-state via Coin 751

## Question
Can an unprivileged attacker entering through the WebSocket event subscription in `Coin` (packages/api/src/@types/Coin.ts) control large numeric fields near JS precision limits during a pending modal confirmation and drive the sequence import -> parse -> preview -> submit so the GUI would correlate a command response to the wrong pending request, violating the invariant that RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/api/src/@types/Coin.ts` / `Coin`
- Entrypoint: WebSocket event subscription
- Attacker controls: large numeric fields near JS precision limits; during a pending modal confirmation
- Exploit idea: correlate a command response to the wrong pending request
- Invariant to test: RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
