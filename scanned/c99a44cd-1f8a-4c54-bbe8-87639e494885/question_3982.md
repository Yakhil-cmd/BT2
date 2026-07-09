# Q3982: Accept zero or identity input

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` with attacker-chosen `v` and make `set_non_identity_constant` accept a zero or identity-valued `interpolation set` that should be rejected, causing Cryptographic flaws?

## Target
- File/function: `src/crypto/polynomials.rs::set_non_identity_constant`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `v`
- Exploit idea: Inject zero, identity, or empty-form `interpolation set` values exactly where the helper assumes they cannot appear.
- Invariant to test: Zero or identity-valued `interpolation set` inputs must be rejected before any interpolation, proof, or signature step.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Construct a deterministic unit or invariant test around `crypto::polynomials::set_non_identity_constant` that feeds crafted `interpolation set` / `hash output` inputs, then assert whether downstream verification accepts an output that should have been rejected.
