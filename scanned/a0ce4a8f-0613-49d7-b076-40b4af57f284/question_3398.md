# Q3398: rpc-state via index 3398

## Question
Can an unprivileged attacker entering through the RTK query cache update in `index` (packages/wallets/src/utils/index.ts) control RPC error payload shaped like success with precision-boundary values and drive the sequence validate input -> normalize payload -> call RPC so the GUI would mis-handle precision for mojos, royalties, or fees in state, violating the invariant that case conversion must not collapse distinct fields into privileged values, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/wallets/src/utils/index.ts` / `index`
- Entrypoint: RTK query cache update
- Attacker controls: RPC error payload shaped like success; with precision-boundary values
- Exploit idea: mis-handle precision for mojos, royalties, or fees in state
- Invariant to test: case conversion must not collapse distinct fields into privileged values
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
