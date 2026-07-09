# Q3174: Omit context from rerandomization

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `confidential_key_derivation::ckd(...)` and exploit `deserialize` so `encrypted CKD output` is not fully bound to message, participant set, transcript, or presign context, enabling Unauthorized access to MPC key shares or signing capability?

## Target
- File/function: `src/confidential_key_derivation/app_id.rs::deserialize`
- Entrypoint: `confidential_key_derivation::ckd(...)`
- Attacker controls: `deserializer`, `protocol message timing`
- Exploit idea: Change message, signer set, or transcript context while reusing the same `encrypted CKD output` helper material.
- Invariant to test: Derived or rerandomized `encrypted CKD output` outputs must be bound to message, signer set, and transcript context.
- Expected Immunefi impact: Unauthorized access to MPC key shares or signing capability
- Fast validation: Run two or more local protocol instances around `confidential_key_derivation::ckd(...)`, let one malicious participant inject conflicting, replayed, or cross-context `encrypted CKD output` data into `deserialize`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
