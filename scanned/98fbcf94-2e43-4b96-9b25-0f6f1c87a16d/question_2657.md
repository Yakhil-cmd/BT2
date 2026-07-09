# Q2657: Leak sensitive state through output

## Question
Can a single malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, or `refresh(...)` and choose `threshold`, `commitment_i`, `protocol message timing` so repeated calls to `insert_identity_if_missing` expose share-dependent structure in `session_id` or `coefficient commitment` that should stay hidden, causing Information disclosure of sensitive MPC state?

## Target
- File/function: `src/dkg.rs::insert_identity_if_missing`
- Entrypoint: `keygen(...)`, `reshare(...)`, or `refresh(...)`
- Attacker controls: `threshold`, `commitment_i`, `protocol message timing`
- Exploit idea: Query `session_id` repeatedly under attacker-chosen inputs and inspect whether the public output leaks share-dependent structure.
- Invariant to test: Public outputs must not leak hidden share-dependent information about `session_id` or `coefficient commitment`.
- Expected Immunefi impact: Information disclosure of sensitive MPC state
- Fast validation: Run two or more local protocol instances around `keygen(...)`, `reshare(...)`, or `refresh(...)`, let one malicious participant inject conflicting, replayed, or cross-context `session_id` data into `insert_identity_if_missing`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
