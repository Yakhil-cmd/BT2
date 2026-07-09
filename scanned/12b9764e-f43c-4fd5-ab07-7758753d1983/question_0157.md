# Q157: Swap participant ordering

## Question
Can a single malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, or `refresh(...)` with crafted `participant`, `threshold`, `old_participants`, `session_id`, `protocol message timing` and exploit `verify_proof_of_knowledge` so participant ordering or identifier mapping for `of` differs across nodes, breaking signer-set consistency and leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/dkg.rs::verify_proof_of_knowledge`
- Entrypoint: `keygen(...)`, `reshare(...)`, or `refresh(...)`
- Attacker controls: `participant`, `threshold`, `old_participants`, `session_id`, `protocol message timing`
- Exploit idea: Reorder or relabel participant-specific `of` values and look for divergent Lagrange or identifier handling.
- Invariant to test: Participant identifiers, ordering, and Lagrange weights must map 1:1 to the intended signer set.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `keygen(...)`, `reshare(...)`, or `refresh(...)`, let one malicious participant inject conflicting, replayed, or cross-context `of` data into `verify_proof_of_knowledge`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
