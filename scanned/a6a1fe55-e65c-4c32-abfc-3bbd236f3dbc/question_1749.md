# Q1749: rpc-state via toSafeNumber 1749

## Question
Can an unprivileged attacker entering through the WebSocket event subscription in `toSafeNumber` (packages/api/src/utils/toSafeNumber.ts) control large numeric fields near JS precision limits with reordered RPC events and drive the sequence validate input -> normalize payload -> call RPC so the GUI would transform attacker-controlled keys into privileged fields, violating the invariant that RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/api/src/utils/toSafeNumber.ts` / `toSafeNumber`
- Entrypoint: WebSocket event subscription
- Attacker controls: large numeric fields near JS precision limits; with reordered RPC events
- Exploit idea: transform attacker-controlled keys into privileged fields
- Invariant to test: RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
