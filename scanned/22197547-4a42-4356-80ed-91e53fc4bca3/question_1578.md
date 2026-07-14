# Q1578: rpc-state via if 1578

## Question
Can an unprivileged attacker entering through the WebSocket event subscription in `if` (packages/gui/src/electron/utils/sanitizeNumber.ts) control RPC error payload shaped like success with a stale Redux cache and drive the sequence fetch -> cache -> refresh -> submit so the GUI would mis-handle precision for mojos, royalties, or fees in state, violating the invariant that error states must not be treated as successful authorization, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/gui/src/electron/utils/sanitizeNumber.ts` / `if`
- Entrypoint: WebSocket event subscription
- Attacker controls: RPC error payload shaped like success; with a stale Redux cache
- Exploit idea: mis-handle precision for mojos, royalties, or fees in state
- Invariant to test: error states must not be treated as successful authorization
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
