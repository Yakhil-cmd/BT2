# Q3945: Leak sensitive state through output

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and choose `domain-separated hash`, `serialized scalar` so repeated calls to `extend_with_zero` expose share-dependent structure in `Lagrange coefficient` or `Lagrange coefficient` that should stay hidden, causing Information disclosure of sensitive MPC state?

## Target
- File/function: `src/crypto/polynomials.rs::extend_with_zero`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `domain-separated hash`, `serialized scalar`
- Exploit idea: Query `Lagrange coefficient` repeatedly under attacker-chosen inputs and inspect whether the public output leaks share-dependent structure.
- Invariant to test: Public outputs must not leak hidden share-dependent information about `Lagrange coefficient` or `Lagrange coefficient`.
- Expected Immunefi impact: Information disclosure of sensitive MPC state
- Fast validation: Construct a deterministic unit or invariant test around `crypto::polynomials::extend_with_zero` that feeds crafted `Lagrange coefficient` / `Lagrange coefficient` inputs, then assert whether downstream verification accepts an output that should have been rejected.
