# Q3200: Omit context from rerandomization

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `confidential_key_derivation::ckd(...)` and exploit `deserialize_reader` so `app_id` is not fully bound to message, participant set, transcript, or presign context, enabling Unauthorized access to MPC key shares or signing capability?

## Target
- File/function: `src/confidential_key_derivation/app_id.rs::deserialize_reader`
- Entrypoint: `confidential_key_derivation::ckd(...)`
- Attacker controls: `reader`, `protocol message timing`
- Exploit idea: Change message, signer set, or transcript context while reusing the same `app_id` helper material.
- Invariant to test: Derived or rerandomized `app_id` outputs must be bound to message, signer set, and transcript context.
- Expected Immunefi impact: Unauthorized access to MPC key shares or signing capability
- Fast validation: Run two or more local protocol instances around `confidential_key_derivation::ckd(...)`, let one malicious participant inject conflicting, replayed, or cross-context `app_id` data into `deserialize_reader`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
