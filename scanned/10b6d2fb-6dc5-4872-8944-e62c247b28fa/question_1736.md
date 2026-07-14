# Q1736: rpc-state via constructor 1736

## Question
Can an unprivileged attacker entering through the RTK query cache update in `constructor` (packages/api/src/services/FullNode.ts) control large numeric fields near JS precision limits after a network switch and drive the sequence select -> edit backing object -> submit so the GUI would mis-handle precision for mojos, royalties, or fees in state, violating the invariant that RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/api/src/services/FullNode.ts` / `constructor`
- Entrypoint: RTK query cache update
- Attacker controls: large numeric fields near JS precision limits; after a network switch
- Exploit idea: mis-handle precision for mojos, royalties, or fees in state
- Invariant to test: RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
