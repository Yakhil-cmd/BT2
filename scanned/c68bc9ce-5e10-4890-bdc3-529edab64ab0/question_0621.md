# Q621: Bypass proof binding

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `confidential_key_derivation::ckd(...)` and control `participants`, `key_pair`, `app_id`, `app_pk`, `protocol message timing` so `do_ckd_coordinator` accepts a `big_c` proof, commitment, or hash that is not bound to the exact sender/session/role context, leading to Unauthorized access to MPC key shares or signing capability?

## Target
- File/function: `src/confidential_key_derivation/protocol.rs::do_ckd_coordinator`
- Entrypoint: `confidential_key_derivation::ckd(...)`
- Attacker controls: `participants`, `key_pair`, `app_id`, `app_pk`, `protocol message timing`
- Exploit idea: Pair a proof/hash for one sender or session with a different `big_c` payload and see whether the binding check is incomplete.
- Invariant to test: Proofs, commitments, and hashes must be bound to the exact sender, session, and role they certify.
- Expected Immunefi impact: Unauthorized access to MPC key shares or signing capability
- Fast validation: Run two or more local protocol instances around `confidential_key_derivation::ckd(...)`, let one malicious participant inject conflicting, replayed, or cross-context `big_c` data into `do_ckd_coordinator`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
