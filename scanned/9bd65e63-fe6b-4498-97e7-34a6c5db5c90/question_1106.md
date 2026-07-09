# Q1106: Replay stale context

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `ecdsa::ot_based_ecdsa::sign::sign(...)` and replay a stale `presignature` into `sign` by controlling `participants`, `coordinator`, `threshold`, `public_key`, `protocol message timing`, so this code path accepts state from an earlier session as current and eventually enables Bypass of threshold signature requirements?

## Target
- File/function: `src/ecdsa/ot_based_ecdsa/sign.rs::sign`
- Entrypoint: `ecdsa::ot_based_ecdsa::sign::sign(...)`
- Attacker controls: `participants`, `coordinator`, `threshold`, `public_key`, `protocol message timing`
- Exploit idea: Capture a valid `presignature` from one run and inject it into a fresh run with overlapping participants before the expected check fires.
- Invariant to test: `presignature` must be bound to the live session, participant set, and exact transcript that consumes it.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `ecdsa::ot_based_ecdsa::sign::sign(...)`, let one malicious participant inject conflicting, replayed, or cross-context `presignature` data into `sign`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
