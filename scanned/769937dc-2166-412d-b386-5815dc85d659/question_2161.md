# Q2161: rpc-state via getNetworkInfo 2161

## Question
Can an unprivileged attacker entering through the RTK query cache update in `getNetworkInfo` (packages/gui/src/electron/api/getNetworkInfo.ts) control large numeric fields near JS precision limits during a pending modal confirmation and drive the sequence preview -> mutate controlled state -> confirm so the GUI would mis-handle precision for mojos, royalties, or fees in state, violating the invariant that case conversion must not collapse distinct fields into privileged values, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/gui/src/electron/api/getNetworkInfo.ts` / `getNetworkInfo`
- Entrypoint: RTK query cache update
- Attacker controls: large numeric fields near JS precision limits; during a pending modal confirmation
- Exploit idea: mis-handle precision for mojos, royalties, or fees in state
- Invariant to test: case conversion must not collapse distinct fields into privileged values
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
