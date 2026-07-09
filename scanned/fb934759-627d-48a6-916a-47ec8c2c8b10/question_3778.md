# Q3778: Accept zero or identity input

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` with attacker-chosen `rhs` and make `add` accept a zero or identity-valued `serialized scalar` that should be rejected, causing Cryptographic flaws?

## Target
- File/function: `src/crypto/polynomials.rs::add`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `rhs`
- Exploit idea: Inject zero, identity, or empty-form `serialized scalar` values exactly where the helper assumes they cannot appear.
- Invariant to test: Zero or identity-valued `serialized scalar` inputs must be rejected before any interpolation, proof, or signature step.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Construct a deterministic unit or invariant test around `crypto::polynomials::add` that feeds crafted `serialized scalar` / `serialized scalar` inputs, then assert whether downstream verification accepts an output that should have been rejected.
