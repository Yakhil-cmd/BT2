# Q1901: Bypass proof binding

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `confidential_key_derivation::ckd(...)` and control `participants`, `coordinator`, `key_pair`, `app_id`, `protocol message timing` so `run_ckd_protocol` accepts a `run` proof, commitment, or hash that is not bound to the exact sender/session/role context, leading to Unauthorized access to MPC key shares or signing capability?

## Target
- File/function: `src/confidential_key_derivation/protocol.rs::run_ckd_protocol`
- Entrypoint: `confidential_key_derivation::ckd(...)`
- Attacker controls: `participants`, `coordinator`, `key_pair`, `app_id`, `protocol message timing`
- Exploit idea: Pair a proof/hash for one sender or session with a different `run` payload and see whether the binding check is incomplete.
- Invariant to test: Proofs, commitments, and hashes must be bound to the exact sender, session, and role they certify.
- Expected Immunefi impact: Unauthorized access to MPC key shares or signing capability
- Fast validation: Run two or more local protocol instances around `confidential_key_derivation::ckd(...)`, let one malicious participant inject conflicting, replayed, or cross-context `run` data into `run_ckd_protocol`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
