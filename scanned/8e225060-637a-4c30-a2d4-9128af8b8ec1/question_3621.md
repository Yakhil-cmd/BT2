# Q3621: Replay stale context

## Question
Can a malicious network peer or malicious coordinator below threshold enter through `Protocol::message(...)` during `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and replay a stale `shared channel` into `root_shared` by controlling `channel tag`, `waitpoint`, `protocol message timing`, so this code path accepts state from an earlier session as current and eventually enables Bypass of threshold signature requirements?

## Target
- File/function: `src/protocol/internal.rs::root_shared`
- Entrypoint: `Protocol::message(...)` during `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `channel tag`, `waitpoint`, `protocol message timing`
- Exploit idea: Capture a valid `shared channel` from one run and inject it into a fresh run with overlapping participants before the expected check fires.
- Invariant to test: `shared channel` must be bound to the live session, participant set, and exact transcript that consumes it.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `Protocol::message(...)` during `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`, let one malicious participant inject conflicting, replayed, or cross-context `shared channel` data into `root_shared`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
