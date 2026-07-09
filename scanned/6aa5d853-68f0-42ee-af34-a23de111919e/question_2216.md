# Q2216: Interpolate on malicious subset

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and steer `values` so `batch_invert` interpolates `polynomial commitment` over an attacker-influenced subset that is algebraically inconsistent with the honest transcript, leading to Cryptographic flaws?

## Target
- File/function: `src/crypto/polynomials.rs::batch_invert`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `values`
- Exploit idea: Force interpolation over attacker-selected indices, then compare the reconstructed `polynomial commitment` against the honest relation.
- Invariant to test: Interpolation must only use the intended threshold-sized honest-consistent subset for `polynomial commitment`.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Construct a deterministic unit or invariant test around `crypto::polynomials::batch_invert` that feeds crafted `polynomial commitment` / `Lagrange coefficient` inputs, then assert whether downstream verification accepts an output that should have been rejected.
