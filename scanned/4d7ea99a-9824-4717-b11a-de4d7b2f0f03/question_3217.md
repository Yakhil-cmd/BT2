# Q3217: Swap participant ordering

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `confidential_key_derivation::ckd(...)` with crafted `id`, `protocol message timing` and exploit `try_new` so participant ordering or identifier mapping for `big_y` differs across nodes, breaking signer-set consistency and leading to Unauthorized access to MPC key shares or signing capability?

## Target
- File/function: `src/confidential_key_derivation/app_id.rs::try_new`
- Entrypoint: `confidential_key_derivation::ckd(...)`
- Attacker controls: `id`, `protocol message timing`
- Exploit idea: Reorder or relabel participant-specific `big_y` values and look for divergent Lagrange or identifier handling.
- Invariant to test: Participant identifiers, ordering, and Lagrange weights must map 1:1 to the intended signer set.
- Expected Immunefi impact: Unauthorized access to MPC key shares or signing capability
- Fast validation: Run two or more local protocol instances around `confidential_key_derivation::ckd(...)`, let one malicious participant inject conflicting, replayed, or cross-context `big_y` data into `try_new`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
