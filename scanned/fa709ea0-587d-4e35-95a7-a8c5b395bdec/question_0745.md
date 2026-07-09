# Q745: Replay stale context

## Question
Can a single malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, or `refresh(...)` and replay a stale `validate_received_share` into `validate_received_share` by controlling `commitment`, `from`, `signing_share_from`, `protocol message timing`, so this code path accepts state from an earlier session as current and eventually enables Bypass of threshold signature requirements?

## Target
- File/function: `src/dkg.rs::validate_received_share`
- Entrypoint: `keygen(...)`, `reshare(...)`, or `refresh(...)`
- Attacker controls: `commitment`, `from`, `signing_share_from`, `protocol message timing`
- Exploit idea: Capture a valid `validate_received_share` from one run and inject it into a fresh run with overlapping participants before the expected check fires.
- Invariant to test: `validate_received_share` must be bound to the live session, participant set, and exact transcript that consumes it.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `keygen(...)`, `reshare(...)`, or `refresh(...)`, let one malicious participant inject conflicting, replayed, or cross-context `validate_received_share` data into `validate_received_share`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
