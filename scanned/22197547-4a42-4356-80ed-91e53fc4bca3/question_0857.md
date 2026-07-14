# Q857: rpc-state via useShowError 857

## Question
Can an unprivileged attacker entering through the WebSocket event subscription in `useShowError` (packages/core/src/hooks/useShowError.tsx) control RPC error payload shaped like success with a delayed metadata fetch and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would correlate a command response to the wrong pending request, violating the invariant that error states must not be treated as successful authorization, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/core/src/hooks/useShowError.tsx` / `useShowError`
- Entrypoint: WebSocket event subscription
- Attacker controls: RPC error payload shaped like success; with a delayed metadata fetch
- Exploit idea: correlate a command response to the wrong pending request
- Invariant to test: error states must not be treated as successful authorization
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
