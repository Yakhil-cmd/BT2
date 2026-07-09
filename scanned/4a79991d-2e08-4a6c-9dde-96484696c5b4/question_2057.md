# Q2057: Accept zero or identity input

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` with attacker-chosen `val`, `r` and make `check` accept a zero or identity-valued `interpolation set` that should be rejected, causing Cryptographic flaws?

## Target
- File/function: `src/crypto/commitment.rs::check`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `val`, `r`
- Exploit idea: Inject zero, identity, or empty-form `interpolation set` values exactly where the helper assumes they cannot appear.
- Invariant to test: Zero or identity-valued `interpolation set` inputs must be rejected before any interpolation, proof, or signature step.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Construct a deterministic unit or invariant test around `crypto::commitment::check` that feeds crafted `interpolation set` / `polynomial commitment` inputs, then assert whether downstream verification accepts an output that should have been rejected.
