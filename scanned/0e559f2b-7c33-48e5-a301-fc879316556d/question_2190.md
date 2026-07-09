# Q2190: Interpolate on malicious subset

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and steer `points_set`, `x` so `batch_compute_lagrange_coefficients` interpolates `coefficients` over an attacker-influenced subset that is algebraically inconsistent with the honest transcript, leading to Cryptographic flaws?

## Target
- File/function: `src/crypto/polynomials.rs::batch_compute_lagrange_coefficients`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `points_set`, `x`
- Exploit idea: Force interpolation over attacker-selected indices, then compare the reconstructed `coefficients` against the honest relation.
- Invariant to test: Interpolation must only use the intended threshold-sized honest-consistent subset for `coefficients`.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Construct a deterministic unit or invariant test around `crypto::polynomials::batch_compute_lagrange_coefficients` that feeds crafted `coefficients` / `Lagrange coefficient` inputs, then assert whether downstream verification accepts an output that should have been rejected.
