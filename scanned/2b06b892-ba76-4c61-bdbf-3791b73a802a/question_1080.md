# Q1080: Replay stale context

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `ecdsa::ot_based_ecdsa::presign(...)`, `ecdsa::ot_based_ecdsa::sign(...)`, or the triple-generation pipeline` and replay a stale `triple share` into `fut_wrapper` by controlling `participants`, `coordinator`, `public_key`, `presignature`, `protocol message timing`, so this code path accepts state from an earlier session as current and eventually enables Bypass of threshold signature requirements?

## Target
- File/function: `src/ecdsa/ot_based_ecdsa/sign.rs::fut_wrapper`
- Entrypoint: `ecdsa::ot_based_ecdsa::presign(...)`, `ecdsa::ot_based_ecdsa::sign(...)`, or the triple-generation pipeline`
- Attacker controls: `participants`, `coordinator`, `public_key`, `presignature`, `protocol message timing`
- Exploit idea: Capture a valid `triple share` from one run and inject it into a fresh run with overlapping participants before the expected check fires.
- Invariant to test: `triple share` must be bound to the live session, participant set, and exact transcript that consumes it.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `ecdsa::ot_based_ecdsa::presign(...)`, `ecdsa::ot_based_ecdsa::sign(...)`, or the triple-generation pipeline`, let one malicious participant inject conflicting, replayed, or cross-context `triple share` data into `fut_wrapper`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
