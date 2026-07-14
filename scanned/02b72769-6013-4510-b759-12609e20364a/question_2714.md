# Q2714: rpc-state via handleSetIsHidden 2714

## Question
Can an unprivileged attacker entering through the service command response correlation in `handleSetIsHidden` (packages/core/src/hooks/useHiddenList.ts) control out-of-order event and query responses with a redirected remote resource and drive the sequence open notification -> resolve details -> execute so the GUI would transform attacker-controlled keys into privileged fields, violating the invariant that error states must not be treated as successful authorization, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/core/src/hooks/useHiddenList.ts` / `handleSetIsHidden`
- Entrypoint: service command response correlation
- Attacker controls: out-of-order event and query responses; with a redirected remote resource
- Exploit idea: transform attacker-controlled keys into privileged fields
- Invariant to test: error states must not be treated as successful authorization
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
