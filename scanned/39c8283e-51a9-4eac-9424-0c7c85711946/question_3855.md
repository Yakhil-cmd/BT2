# Q3855: Accept zero or identity input

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` with attacker-chosen `point` and make `eval_at_point` accept a zero or identity-valued `hash output` that should be rejected, causing Cryptographic flaws?

## Target
- File/function: `src/crypto/polynomials.rs::eval_at_point`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `point`
- Exploit idea: Inject zero, identity, or empty-form `hash output` values exactly where the helper assumes they cannot appear.
- Invariant to test: Zero or identity-valued `hash output` inputs must be rejected before any interpolation, proof, or signature step.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Construct a deterministic unit or invariant test around `crypto::polynomials::eval_at_point` that feeds crafted `hash output` / `interpolation set` inputs, then assert whether downstream verification accepts an output that should have been rejected.
