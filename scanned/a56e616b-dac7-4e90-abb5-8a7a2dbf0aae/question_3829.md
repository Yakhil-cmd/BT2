# Q3829: Accept zero or identity input

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` with attacker-chosen `participant` and make `eval_at_participant` accept a zero or identity-valued `serialized scalar` that should be rejected, causing Cryptographic flaws?

## Target
- File/function: `src/crypto/polynomials.rs::eval_at_participant`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `participant`
- Exploit idea: Inject zero, identity, or empty-form `serialized scalar` values exactly where the helper assumes they cannot appear.
- Invariant to test: Zero or identity-valued `serialized scalar` inputs must be rejected before any interpolation, proof, or signature step.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Construct a deterministic unit or invariant test around `crypto::polynomials::eval_at_participant` that feeds crafted `serialized scalar` / `serialized scalar` inputs, then assert whether downstream verification accepts an output that should have been rejected.
