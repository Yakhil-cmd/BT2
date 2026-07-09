# Q2212: Accept zero or identity input

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` with attacker-chosen `values` and make `batch_invert` accept a zero or identity-valued `polynomial commitment` that should be rejected, causing Cryptographic flaws?

## Target
- File/function: `src/crypto/polynomials.rs::batch_invert`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `values`
- Exploit idea: Inject zero, identity, or empty-form `polynomial commitment` values exactly where the helper assumes they cannot appear.
- Invariant to test: Zero or identity-valued `polynomial commitment` inputs must be rejected before any interpolation, proof, or signature step.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Construct a deterministic unit or invariant test around `crypto::polynomials::batch_invert` that feeds crafted `polynomial commitment` / `polynomial` inputs, then assert whether downstream verification accepts an output that should have been rejected.
