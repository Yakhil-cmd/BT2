# Q797: rpc-state via index 797

## Question
Can an unprivileged attacker entering through the WebSocket event subscription in `index` (packages/api/src/constants/index.ts) control response object with duplicate camelCase/snake_case keys after canceling and reopening the dialog and drive the sequence validate input -> normalize payload -> call RPC so the GUI would mis-handle precision for mojos, royalties, or fees in state, violating the invariant that case conversion must not collapse distinct fields into privileged values, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/api/src/constants/index.ts` / `index`
- Entrypoint: WebSocket event subscription
- Attacker controls: response object with duplicate camelCase/snake_case keys; after canceling and reopening the dialog
- Exploit idea: mis-handle precision for mojos, royalties, or fees in state
- Invariant to test: case conversion must not collapse distinct fields into privileged values
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
