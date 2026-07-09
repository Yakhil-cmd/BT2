# Q1: Replay stale context

## Question
Can a single malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, or `refresh(...)` and replay a stale `received share` into `assert_key_invariants` by controlling `participants`, `threshold`, `protocol message timing`, so this code path accepts state from an earlier session as current and eventually enables Bypass of threshold signature requirements?

## Target
- File/function: `src/dkg.rs::assert_key_invariants`
- Entrypoint: `keygen(...)`, `reshare(...)`, or `refresh(...)`
- Attacker controls: `participants`, `threshold`, `protocol message timing`
- Exploit idea: Capture a valid `received share` from one run and inject it into a fresh run with overlapping participants before the expected check fires.
- Invariant to test: `received share` must be bound to the live session, participant set, and exact transcript that consumes it.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `keygen(...)`, `reshare(...)`, or `refresh(...)`, let one malicious participant inject conflicting, replayed, or cross-context `received share` data into `assert_key_invariants`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
