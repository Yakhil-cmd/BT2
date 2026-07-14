# Q947: rpc-state via getVC 947

## Question
Can an unprivileged attacker entering through the WebSocket event subscription in `getVC` (packages/api/src/wallets/VC.ts) control response object with duplicate camelCase/snake_case keys with reordered RPC events and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would mis-handle precision for mojos, royalties, or fees in state, violating the invariant that error states must not be treated as successful authorization, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/api/src/wallets/VC.ts` / `getVC`
- Entrypoint: WebSocket event subscription
- Attacker controls: response object with duplicate camelCase/snake_case keys; with reordered RPC events
- Exploit idea: mis-handle precision for mojos, royalties, or fees in state
- Invariant to test: error states must not be treated as successful authorization
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
