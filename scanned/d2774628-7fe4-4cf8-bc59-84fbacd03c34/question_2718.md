# Q2718: rpc-state via useMode 2718

## Question
Can an unprivileged attacker entering through the WebSocket event subscription in `useMode` (packages/core/src/hooks/useMode.ts) control RPC error payload shaped like success with case-normalized identifiers and drive the sequence validate input -> normalize payload -> call RPC so the GUI would transform attacker-controlled keys into privileged fields, violating the invariant that error states must not be treated as successful authorization, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/core/src/hooks/useMode.ts` / `useMode`
- Entrypoint: WebSocket event subscription
- Attacker controls: RPC error payload shaped like success; with case-normalized identifiers
- Exploit idea: transform attacker-controlled keys into privileged fields
- Invariant to test: error states must not be treated as successful authorization
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
