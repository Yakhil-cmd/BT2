# Q3526: rpc-state via useSubscribeToEvent 3526

## Question
Can an unprivileged attacker entering through the WebSocket event subscription in `useSubscribeToEvent` (packages/api-react/src/hooks/useSubscribeToEvent.ts) control large numeric fields near JS precision limits during a pending modal confirmation and drive the sequence preview -> mutate controlled state -> confirm so the GUI would correlate a command response to the wrong pending request, violating the invariant that RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/api-react/src/hooks/useSubscribeToEvent.ts` / `useSubscribeToEvent`
- Entrypoint: WebSocket event subscription
- Attacker controls: large numeric fields near JS precision limits; during a pending modal confirmation
- Exploit idea: correlate a command response to the wrong pending request
- Invariant to test: RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
