# Q2124: Leak sensitive state through output

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and choose `val`, `r` so repeated calls to `compute` expose share-dependent structure in `serialized group element` or `polynomial commitment` that should stay hidden, causing Information disclosure of sensitive MPC state?

## Target
- File/function: `src/crypto/commitment.rs::compute`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `val`, `r`
- Exploit idea: Query `serialized group element` repeatedly under attacker-chosen inputs and inspect whether the public output leaks share-dependent structure.
- Invariant to test: Public outputs must not leak hidden share-dependent information about `serialized group element` or `polynomial commitment`.
- Expected Immunefi impact: Information disclosure of sensitive MPC state
- Fast validation: Construct a deterministic unit or invariant test around `crypto::commitment::compute` that feeds crafted `serialized group element` / `polynomial commitment` inputs, then assert whether downstream verification accepts an output that should have been rejected.
