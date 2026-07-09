# Q770: Leak sensitive state through output

## Question
Can a single malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, or `refresh(...)` and choose `commitment`, `from`, `signing_share_from`, `protocol message timing` so repeated calls to `validate_received_share` expose share-dependent structure in `coefficient commitment` or `session_id` that should stay hidden, causing Information disclosure of sensitive MPC state?

## Target
- File/function: `src/dkg.rs::validate_received_share`
- Entrypoint: `keygen(...)`, `reshare(...)`, or `refresh(...)`
- Attacker controls: `commitment`, `from`, `signing_share_from`, `protocol message timing`
- Exploit idea: Query `coefficient commitment` repeatedly under attacker-chosen inputs and inspect whether the public output leaks share-dependent structure.
- Invariant to test: Public outputs must not leak hidden share-dependent information about `coefficient commitment` or `session_id`.
- Expected Immunefi impact: Information disclosure of sensitive MPC state
- Fast validation: Run two or more local protocol instances around `keygen(...)`, `reshare(...)`, or `refresh(...)`, let one malicious participant inject conflicting, replayed, or cross-context `coefficient commitment` data into `validate_received_share`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
