# Q1743: Replay stale context

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `frost::presign(...)` and replay a stale `participant identifier` into `presign` by controlling `participants`, `args`, `protocol message timing`, so this code path accepts state from an earlier session as current and eventually enables Bypass of threshold signature requirements?

## Target
- File/function: `src/frost/mod.rs::presign`
- Entrypoint: `frost::presign(...)`
- Attacker controls: `participants`, `args`, `protocol message timing`
- Exploit idea: Capture a valid `participant identifier` from one run and inject it into a fresh run with overlapping participants before the expected check fires.
- Invariant to test: `participant identifier` must be bound to the live session, participant set, and exact transcript that consumes it.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `frost::presign(...)`, let one malicious participant inject conflicting, replayed, or cross-context `participant identifier` data into `presign`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
