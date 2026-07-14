# Q1674: rpc-state via dayBefore 1674

## Question
Can an unprivileged attacker entering through the daemon RPC response handling in `dayBefore` (packages/api-react/src/utils/removeOldPoints.ts) control out-of-order event and query responses with precision-boundary values and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would correlate a command response to the wrong pending request, violating the invariant that error states must not be treated as successful authorization, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/api-react/src/utils/removeOldPoints.ts` / `dayBefore`
- Entrypoint: daemon RPC response handling
- Attacker controls: out-of-order event and query responses; with precision-boundary values
- Exploit idea: correlate a command response to the wrong pending request
- Invariant to test: error states must not be treated as successful authorization
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
