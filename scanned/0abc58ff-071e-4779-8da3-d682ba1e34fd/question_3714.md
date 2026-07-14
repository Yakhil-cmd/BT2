# Q3714: rpc-state via sumPoints 3714

## Question
Can an unprivileged attacker entering through the daemon RPC response handling in `sumPoints` (packages/gui/src/util/getPercentPointsSuccessfull.ts) control out-of-order event and query responses with a delayed metadata fetch and drive the sequence select -> edit backing object -> submit so the GUI would mis-handle precision for mojos, royalties, or fees in state, violating the invariant that error states must not be treated as successful authorization, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/gui/src/util/getPercentPointsSuccessfull.ts` / `sumPoints`
- Entrypoint: daemon RPC response handling
- Attacker controls: out-of-order event and query responses; with a delayed metadata fetch
- Exploit idea: mis-handle precision for mojos, royalties, or fees in state
- Invariant to test: error states must not be treated as successful authorization
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
