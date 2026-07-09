# Q1717: Replay stale context

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `frost::eddsa::sign::sign_v2(...)` and replay a stale `coordinator-selected signer set` into `sign_v2` by controlling `participants`, `coordinator`, `threshold`, `presignature`, `protocol message timing`, so this code path accepts state from an earlier session as current and eventually enables Bypass of threshold signature requirements?

## Target
- File/function: `src/frost/eddsa/sign.rs::sign_v2`
- Entrypoint: `frost::eddsa::sign::sign_v2(...)`
- Attacker controls: `participants`, `coordinator`, `threshold`, `presignature`, `protocol message timing`
- Exploit idea: Capture a valid `coordinator-selected signer set` from one run and inject it into a fresh run with overlapping participants before the expected check fires.
- Invariant to test: `coordinator-selected signer set` must be bound to the live session, participant set, and exact transcript that consumes it.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `frost::eddsa::sign::sign_v2(...)`, let one malicious participant inject conflicting, replayed, or cross-context `coordinator-selected signer set` data into `sign_v2`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
