# Q2279: Leak sensitive state through output

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and choose `points_set`, `x_i`, `x` so repeated calls to `compute_lagrange_coefficient` expose share-dependent structure in `coefficient` or `Lagrange coefficient` that should stay hidden, causing Information disclosure of sensitive MPC state?

## Target
- File/function: `src/crypto/polynomials.rs::compute_lagrange_coefficient`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `points_set`, `x_i`, `x`
- Exploit idea: Query `coefficient` repeatedly under attacker-chosen inputs and inspect whether the public output leaks share-dependent structure.
- Invariant to test: Public outputs must not leak hidden share-dependent information about `coefficient` or `Lagrange coefficient`.
- Expected Immunefi impact: Information disclosure of sensitive MPC state
- Fast validation: Construct a deterministic unit or invariant test around `crypto::polynomials::compute_lagrange_coefficient` that feeds crafted `coefficient` / `Lagrange coefficient` inputs, then assert whether downstream verification accepts an output that should have been rejected.
