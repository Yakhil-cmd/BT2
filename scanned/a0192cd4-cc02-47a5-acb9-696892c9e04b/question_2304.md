# Q2304: Leak sensitive state through output

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and choose `identifiers`, `shares`, `point` so repeated calls to `eval_exponent_interpolation` expose share-dependent structure in `eval` or `domain-separated hash` that should stay hidden, causing Information disclosure of sensitive MPC state?

## Target
- File/function: `src/crypto/polynomials.rs::eval_exponent_interpolation`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `identifiers`, `shares`, `point`
- Exploit idea: Query `eval` repeatedly under attacker-chosen inputs and inspect whether the public output leaks share-dependent structure.
- Invariant to test: Public outputs must not leak hidden share-dependent information about `eval` or `domain-separated hash`.
- Expected Immunefi impact: Information disclosure of sensitive MPC state
- Fast validation: Construct a deterministic unit or invariant test around `crypto::polynomials::eval_exponent_interpolation` that feeds crafted `eval` / `domain-separated hash` inputs, then assert whether downstream verification accepts an output that should have been rejected.
