# Q3436: rpc-state via ensureDirectoryExists 3436

## Question
Can an unprivileged attacker entering through the WebSocket event subscription in `ensureDirectoryExists` (packages/gui/src/electron/utils/ensureDirectoryExists.ts) control out-of-order event and query responses with a stale Redux cache and drive the sequence open notification -> resolve details -> execute so the GUI would display one balance/asset state while executing with another, violating the invariant that case conversion must not collapse distinct fields into privileged values, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/gui/src/electron/utils/ensureDirectoryExists.ts` / `ensureDirectoryExists`
- Entrypoint: WebSocket event subscription
- Attacker controls: out-of-order event and query responses; with a stale Redux cache
- Exploit idea: display one balance/asset state while executing with another
- Invariant to test: case conversion must not collapse distinct fields into privileged values
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
