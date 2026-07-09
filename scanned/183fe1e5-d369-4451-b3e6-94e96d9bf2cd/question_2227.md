# Q2227: Leak sensitive state through output

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and choose `values` so repeated calls to `batch_invert` expose share-dependent structure in `domain-separated hash` or `hash output` that should stay hidden, causing Information disclosure of sensitive MPC state?

## Target
- File/function: `src/crypto/polynomials.rs::batch_invert`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `values`
- Exploit idea: Query `domain-separated hash` repeatedly under attacker-chosen inputs and inspect whether the public output leaks share-dependent structure.
- Invariant to test: Public outputs must not leak hidden share-dependent information about `domain-separated hash` or `hash output`.
- Expected Immunefi impact: Information disclosure of sensitive MPC state
- Fast validation: Construct a deterministic unit or invariant test around `crypto::polynomials::batch_invert` that feeds crafted `domain-separated hash` / `hash output` inputs, then assert whether downstream verification accepts an output that should have been rejected.
