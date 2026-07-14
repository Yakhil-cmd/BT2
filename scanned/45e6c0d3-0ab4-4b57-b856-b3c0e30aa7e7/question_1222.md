# Q1222: rpc-state via getKeys 1222

## Question
Can an unprivileged attacker entering through the WebSocket event subscription in `getKeys` (packages/gui/src/electron/api/getKeys.ts) control large numeric fields near JS precision limits with precision-boundary values and drive the sequence preview -> mutate controlled state -> confirm so the GUI would mis-handle precision for mojos, royalties, or fees in state, violating the invariant that case conversion must not collapse distinct fields into privileged values, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/gui/src/electron/api/getKeys.ts` / `getKeys`
- Entrypoint: WebSocket event subscription
- Attacker controls: large numeric fields near JS precision limits; with precision-boundary values
- Exploit idea: mis-handle precision for mojos, royalties, or fees in state
- Invariant to test: case conversion must not collapse distinct fields into privileged values
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
