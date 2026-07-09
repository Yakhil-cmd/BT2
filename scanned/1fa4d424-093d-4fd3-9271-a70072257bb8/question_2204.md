# Q2204: Split global and local checks

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and craft `points_set`, `x` so each local sub-check inside `batch_compute_lagrange_coefficients` accepts its own `serialized group element` fragment, but the combined global statement over `interpolation set` is still false and nevertheless accepted, leading to Cryptographic flaws?

## Target
- File/function: `src/crypto/polynomials.rs::batch_compute_lagrange_coefficients`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `points_set`, `x`
- Exploit idea: Make each local check over `serialized group element` pass independently, then verify whether the combined global statement over `interpolation set` is still false but accepted.
- Invariant to test: Local checks on decomposed subparts of `serialized group element` must imply the global algebraic statement, not merely independent fragments.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Construct a deterministic unit or invariant test around `crypto::polynomials::batch_compute_lagrange_coefficients` that feeds crafted `serialized group element` / `interpolation set` inputs, then assert whether downstream verification accepts an output that should have been rejected.
