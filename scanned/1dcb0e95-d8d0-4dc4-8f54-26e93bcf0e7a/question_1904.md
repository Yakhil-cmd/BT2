# Q1904: Omit context from rerandomization

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `confidential_key_derivation::ckd(...)` and exploit `run_ckd_protocol` so `ckd` is not fully bound to message, participant set, transcript, or presign context, enabling Unauthorized access to MPC key shares or signing capability?

## Target
- File/function: `src/confidential_key_derivation/protocol.rs::run_ckd_protocol`
- Entrypoint: `confidential_key_derivation::ckd(...)`
- Attacker controls: `participants`, `coordinator`, `key_pair`, `app_id`, `protocol message timing`
- Exploit idea: Change message, signer set, or transcript context while reusing the same `ckd` helper material.
- Invariant to test: Derived or rerandomized `ckd` outputs must be bound to message, signer set, and transcript context.
- Expected Immunefi impact: Unauthorized access to MPC key shares or signing capability
- Fast validation: Run two or more local protocol instances around `confidential_key_derivation::ckd(...)`, let one malicious participant inject conflicting, replayed, or cross-context `ckd` data into `run_ckd_protocol`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
