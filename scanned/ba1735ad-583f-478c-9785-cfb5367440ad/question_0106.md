# Q106: Swap participant ordering

## Question
Can a single malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, or `refresh(...)` with crafted `participants`, `threshold`, `old_participants`, `old_public_key`, `protocol message timing` and exploit `do_reshare` so participant ordering or identifier mapping for `old participant set` differs across nodes, breaking signer-set consistency and leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/dkg.rs::do_reshare`
- Entrypoint: `keygen(...)`, `reshare(...)`, or `refresh(...)`
- Attacker controls: `participants`, `threshold`, `old_participants`, `old_public_key`, `protocol message timing`
- Exploit idea: Reorder or relabel participant-specific `old participant set` values and look for divergent Lagrange or identifier handling.
- Invariant to test: Participant identifiers, ordering, and Lagrange weights must map 1:1 to the intended signer set.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `keygen(...)`, `reshare(...)`, or `refresh(...)`, let one malicious participant inject conflicting, replayed, or cross-context `old participant set` data into `do_reshare`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
