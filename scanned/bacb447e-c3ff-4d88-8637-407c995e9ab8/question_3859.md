# Q3859: Interpolate on malicious subset

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and steer `point` so `eval_at_point` interpolates `Lagrange coefficient` over an attacker-influenced subset that is algebraically inconsistent with the honest transcript, leading to Cryptographic flaws?

## Target
- File/function: `src/crypto/polynomials.rs::eval_at_point`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `point`
- Exploit idea: Force interpolation over attacker-selected indices, then compare the reconstructed `Lagrange coefficient` against the honest relation.
- Invariant to test: Interpolation must only use the intended threshold-sized honest-consistent subset for `Lagrange coefficient`.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Construct a deterministic unit or invariant test around `crypto::polynomials::eval_at_point` that feeds crafted `Lagrange coefficient` / `serialized scalar` inputs, then assert whether downstream verification accepts an output that should have been rejected.
