# Q740: rpc-state via removeOldPoints 740

## Question
Can an unprivileged attacker entering through the WebSocket event subscription in `removeOldPoints` (packages/api-react/src/utils/removeOldPoints.ts) control out-of-order event and query responses after a network switch and drive the sequence import -> parse -> preview -> submit so the GUI would mis-handle precision for mojos, royalties, or fees in state, violating the invariant that RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/api-react/src/utils/removeOldPoints.ts` / `removeOldPoints`
- Entrypoint: WebSocket event subscription
- Attacker controls: out-of-order event and query responses; after a network switch
- Exploit idea: mis-handle precision for mojos, royalties, or fees in state
- Invariant to test: RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
