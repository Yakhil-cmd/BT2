# Q78: Replay stale context

## Question
Can a single malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, or `refresh(...)` and replay a stale `received share` into `do_keyshare` by controlling `participants`, `threshold`, `secret`, `old_reshare_package`, `protocol message timing`, so this code path accepts state from an earlier session as current and eventually enables Bypass of threshold signature requirements?

## Target
- File/function: `src/dkg.rs::do_keyshare`
- Entrypoint: `keygen(...)`, `reshare(...)`, or `refresh(...)`
- Attacker controls: `participants`, `threshold`, `secret`, `old_reshare_package`, `protocol message timing`
- Exploit idea: Capture a valid `received share` from one run and inject it into a fresh run with overlapping participants before the expected check fires.
- Invariant to test: `received share` must be bound to the live session, participant set, and exact transcript that consumes it.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `keygen(...)`, `reshare(...)`, or `refresh(...)`, let one malicious participant inject conflicting, replayed, or cross-context `received share` data into `do_keyshare`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
