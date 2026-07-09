# Q1563: Replay stale context

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `ecdsa::robust_ecdsa::presign::presign(...)` and replay a stale `w share` into `presign` by controlling `participants`, `args`, `protocol message timing`, so this code path accepts state from an earlier session as current and eventually enables Bypass of threshold signature requirements?

## Target
- File/function: `src/ecdsa/robust_ecdsa/presign.rs::presign`
- Entrypoint: `ecdsa::robust_ecdsa::presign::presign(...)`
- Attacker controls: `participants`, `args`, `protocol message timing`
- Exploit idea: Capture a valid `w share` from one run and inject it into a fresh run with overlapping participants before the expected check fires.
- Invariant to test: `w share` must be bound to the live session, participant set, and exact transcript that consumes it.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `ecdsa::robust_ecdsa::presign::presign(...)`, let one malicious participant inject conflicting, replayed, or cross-context `w share` data into `presign`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
