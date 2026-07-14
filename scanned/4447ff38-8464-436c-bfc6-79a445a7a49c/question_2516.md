# Q2516: rpc-state via toSnakeCase 2516

## Question
Can an unprivileged attacker entering through the WebSocket event subscription in `toSnakeCase` (packages/gui/src/electron/utils/toSnakeCase.ts) control large numeric fields near JS precision limits after a network switch and drive the sequence select -> edit backing object -> submit so the GUI would mis-handle precision for mojos, royalties, or fees in state, violating the invariant that case conversion must not collapse distinct fields into privileged values, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/gui/src/electron/utils/toSnakeCase.ts` / `toSnakeCase`
- Entrypoint: WebSocket event subscription
- Attacker controls: large numeric fields near JS precision limits; after a network switch
- Exploit idea: mis-handle precision for mojos, royalties, or fees in state
- Invariant to test: case conversion must not collapse distinct fields into privileged values
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
