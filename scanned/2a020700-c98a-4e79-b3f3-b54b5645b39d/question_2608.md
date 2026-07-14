# Q2608: rpc-state via removeOldPoints 2608

## Question
Can an unprivileged attacker entering through the camel/snake case transform path in `removeOldPoints` (packages/api-react/src/utils/removeOldPoints.ts) control large numeric fields near JS precision limits through a batch of rapid user-accessible actions and drive the sequence open notification -> resolve details -> execute so the GUI would display one balance/asset state while executing with another, violating the invariant that RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/api-react/src/utils/removeOldPoints.ts` / `removeOldPoints`
- Entrypoint: camel/snake case transform path
- Attacker controls: large numeric fields near JS precision limits; through a batch of rapid user-accessible actions
- Exploit idea: display one balance/asset state while executing with another
- Invariant to test: RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
