# Q2673: rpc-state via ErrorData 2673

## Question
Can an unprivileged attacker entering through the RTK query cache update in `ErrorData` (packages/api/src/utils/ErrorData.ts) control large numeric fields near JS precision limits with a delayed metadata fetch and drive the sequence select -> edit backing object -> submit so the GUI would mis-handle precision for mojos, royalties, or fees in state, violating the invariant that RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/api/src/utils/ErrorData.ts` / `ErrorData`
- Entrypoint: RTK query cache update
- Attacker controls: large numeric fields near JS precision limits; with a delayed metadata fetch
- Exploit idea: mis-handle precision for mojos, royalties, or fees in state
- Invariant to test: RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
