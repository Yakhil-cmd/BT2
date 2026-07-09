# Q3345: Swap participant ordering

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `confidential_key_derivation::ckd(...)` with crafted `domain`, `msg`, `protocol message timing` and exploit `hash_to_scalar` so participant ordering or identifier mapping for `to` differs across nodes, breaking signer-set consistency and leading to Unauthorized access to MPC key shares or signing capability?

## Target
- File/function: `src/confidential_key_derivation/ciphersuite.rs::hash_to_scalar`
- Entrypoint: `confidential_key_derivation::ckd(...)`
- Attacker controls: `domain`, `msg`, `protocol message timing`
- Exploit idea: Reorder or relabel participant-specific `to` values and look for divergent Lagrange or identifier handling.
- Invariant to test: Participant identifiers, ordering, and Lagrange weights must map 1:1 to the intended signer set.
- Expected Immunefi impact: Unauthorized access to MPC key shares or signing capability
- Fast validation: Run two or more local protocol instances around `confidential_key_derivation::ckd(...)`, let one malicious participant inject conflicting, replayed, or cross-context `to` data into `hash_to_scalar`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
