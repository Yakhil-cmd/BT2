# Q29: Swap participant ordering

## Question
Can a single malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, or `refresh(...)` with crafted `participants`, `threshold`, `old_participants`, `old_threshold`, `protocol message timing` and exploit `assert_reshare_keys_invariants` so participant ordering or identifier mapping for `session_id` differs across nodes, breaking signer-set consistency and leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/dkg.rs::assert_reshare_keys_invariants`
- Entrypoint: `keygen(...)`, `reshare(...)`, or `refresh(...)`
- Attacker controls: `participants`, `threshold`, `old_participants`, `old_threshold`, `protocol message timing`
- Exploit idea: Reorder or relabel participant-specific `session_id` values and look for divergent Lagrange or identifier handling.
- Invariant to test: Participant identifiers, ordering, and Lagrange weights must map 1:1 to the intended signer set.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `keygen(...)`, `reshare(...)`, or `refresh(...)`, let one malicious participant inject conflicting, replayed, or cross-context `session_id` data into `assert_reshare_keys_invariants`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
