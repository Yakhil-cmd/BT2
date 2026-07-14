# Q1673: rpc-state via if 1673

## Question
Can an unprivileged attacker entering through the WebSocket event subscription in `if` (packages/api-react/src/utils/reduxToolkitEndpointAbstractions.ts) control large numeric fields near JS precision limits with hidden Unicode characters and drive the sequence preview -> mutate controlled state -> confirm so the GUI would display one balance/asset state while executing with another, violating the invariant that RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/api-react/src/utils/reduxToolkitEndpointAbstractions.ts` / `if`
- Entrypoint: WebSocket event subscription
- Attacker controls: large numeric fields near JS precision limits; with hidden Unicode characters
- Exploit idea: display one balance/asset state while executing with another
- Invariant to test: RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
