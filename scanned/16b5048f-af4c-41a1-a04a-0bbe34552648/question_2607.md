# Q2607: Leak sensitive state through output

## Question
Can a single malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, or `refresh(...)` and choose `participants`, `session_id`, `protocol message timing` so repeated calls to `broadcast_success` expose share-dependent structure in `domain_separator` or `commitment hash` that should stay hidden, causing Information disclosure of sensitive MPC state?

## Target
- File/function: `src/dkg.rs::broadcast_success`
- Entrypoint: `keygen(...)`, `reshare(...)`, or `refresh(...)`
- Attacker controls: `participants`, `session_id`, `protocol message timing`
- Exploit idea: Query `domain_separator` repeatedly under attacker-chosen inputs and inspect whether the public output leaks share-dependent structure.
- Invariant to test: Public outputs must not leak hidden share-dependent information about `domain_separator` or `commitment hash`.
- Expected Immunefi impact: Information disclosure of sensitive MPC state
- Fast validation: Run two or more local protocol instances around `keygen(...)`, `reshare(...)`, or `refresh(...)`, let one malicious participant inject conflicting, replayed, or cross-context `domain_separator` data into `broadcast_success`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
