# Q566: rpc-state via ServiceHumanName 566

## Question
Can an unprivileged attacker entering through the WebSocket event subscription in `ServiceHumanName` (packages/api/src/constants/ServiceHumanName.ts) control large numeric fields near JS precision limits after a profile switch and drive the sequence download or render content -> trigger linked wallet action so the GUI would mis-handle precision for mojos, royalties, or fees in state, violating the invariant that RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/api/src/constants/ServiceHumanName.ts` / `ServiceHumanName`
- Entrypoint: WebSocket event subscription
- Attacker controls: large numeric fields near JS precision limits; after a profile switch
- Exploit idea: mis-handle precision for mojos, royalties, or fees in state
- Invariant to test: RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
