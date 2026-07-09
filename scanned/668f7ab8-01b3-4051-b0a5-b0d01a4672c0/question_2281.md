# Q2281: Split global and local checks

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and craft `points_set`, `x_i`, `x` so each local sub-check inside `compute_lagrange_coefficient` accepts its own `hash output` fragment, but the combined global statement over `Lagrange coefficient` is still false and nevertheless accepted, leading to Cryptographic flaws?

## Target
- File/function: `src/crypto/polynomials.rs::compute_lagrange_coefficient`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `points_set`, `x_i`, `x`
- Exploit idea: Make each local check over `hash output` pass independently, then verify whether the combined global statement over `Lagrange coefficient` is still false but accepted.
- Invariant to test: Local checks on decomposed subparts of `hash output` must imply the global algebraic statement, not merely independent fragments.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Construct a deterministic unit or invariant test around `crypto::polynomials::compute_lagrange_coefficient` that feeds crafted `hash output` / `Lagrange coefficient` inputs, then assert whether downstream verification accepts an output that should have been rejected.
