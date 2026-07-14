# Q3429: rpc-state via if 3429

## Question
Can an unprivileged attacker entering through the RTK query cache update in `if` (packages/gui/src/electron/main.tsx) control large numeric fields near JS precision limits with case-normalized identifiers and drive the sequence open notification -> resolve details -> execute so the GUI would mis-handle precision for mojos, royalties, or fees in state, violating the invariant that error states must not be treated as successful authorization, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/gui/src/electron/main.tsx` / `if`
- Entrypoint: RTK query cache update
- Attacker controls: large numeric fields near JS precision limits; with case-normalized identifiers
- Exploit idea: mis-handle precision for mojos, royalties, or fees in state
- Invariant to test: error states must not be treated as successful authorization
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
