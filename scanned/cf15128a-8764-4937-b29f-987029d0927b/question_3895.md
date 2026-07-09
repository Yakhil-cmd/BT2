# Q3895: Leak sensitive state through output

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and choose `domain-separated hash`, `serialized scalar` so repeated calls to `eval_at_zero` expose share-dependent structure in `zero` or `polynomial commitment` that should stay hidden, causing Information disclosure of sensitive MPC state?

## Target
- File/function: `src/crypto/polynomials.rs::eval_at_zero`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `domain-separated hash`, `serialized scalar`
- Exploit idea: Query `zero` repeatedly under attacker-chosen inputs and inspect whether the public output leaks share-dependent structure.
- Invariant to test: Public outputs must not leak hidden share-dependent information about `zero` or `polynomial commitment`.
- Expected Immunefi impact: Information disclosure of sensitive MPC state
- Fast validation: Construct a deterministic unit or invariant test around `crypto::polynomials::eval_at_zero` that feeds crafted `zero` / `polynomial commitment` inputs, then assert whether downstream verification accepts an output that should have been rejected.
