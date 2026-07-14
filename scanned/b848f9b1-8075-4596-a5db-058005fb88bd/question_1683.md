# Q1683: rpc-state via CalculateRoyaltiesResponse 1683

## Question
Can an unprivileged attacker entering through the daemon RPC response handling in `CalculateRoyaltiesResponse` (packages/api/src/@types/CalculateRoyaltiesResponse.ts) control out-of-order event and query responses after a failed RPC response and drive the sequence open notification -> resolve details -> execute so the GUI would mis-handle precision for mojos, royalties, or fees in state, violating the invariant that error states must not be treated as successful authorization, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/api/src/@types/CalculateRoyaltiesResponse.ts` / `CalculateRoyaltiesResponse`
- Entrypoint: daemon RPC response handling
- Attacker controls: out-of-order event and query responses; after a failed RPC response
- Exploit idea: mis-handle precision for mojos, royalties, or fees in state
- Invariant to test: error states must not be treated as successful authorization
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
