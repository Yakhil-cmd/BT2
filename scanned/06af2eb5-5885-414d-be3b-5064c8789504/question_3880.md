# Q3880: Accept zero or identity input

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` with attacker-chosen `serialized scalar`, `serialized group element` and make `eval_at_zero` accept a zero or identity-valued `at` that should be rejected, causing Cryptographic flaws?

## Target
- File/function: `src/crypto/polynomials.rs::eval_at_zero`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `serialized scalar`, `serialized group element`
- Exploit idea: Inject zero, identity, or empty-form `at` values exactly where the helper assumes they cannot appear.
- Invariant to test: Zero or identity-valued `at` inputs must be rejected before any interpolation, proof, or signature step.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Construct a deterministic unit or invariant test around `crypto::polynomials::eval_at_zero` that feeds crafted `at` / `eval` inputs, then assert whether downstream verification accepts an output that should have been rejected.
