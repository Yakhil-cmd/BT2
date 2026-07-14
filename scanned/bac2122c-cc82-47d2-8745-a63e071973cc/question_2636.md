# Q2636: rpc-state via Peak 2636

## Question
Can an unprivileged attacker entering through the WebSocket event subscription in `Peak` (packages/api/src/@types/Peak.ts) control RPC error payload shaped like success with a redirected remote resource and drive the sequence validate input -> normalize payload -> call RPC so the GUI would display one balance/asset state while executing with another, violating the invariant that error states must not be treated as successful authorization, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/api/src/@types/Peak.ts` / `Peak`
- Entrypoint: WebSocket event subscription
- Attacker controls: RPC error payload shaped like success; with a redirected remote resource
- Exploit idea: display one balance/asset state while executing with another
- Invariant to test: error states must not be treated as successful authorization
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
