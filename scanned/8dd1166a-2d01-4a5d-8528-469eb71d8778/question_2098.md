# Q2098: Leak sensitive state through output

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and choose `val` so repeated calls to `commit` expose share-dependent structure in `polynomial commitment` or `serialized scalar` that should stay hidden, causing Information disclosure of sensitive MPC state?

## Target
- File/function: `src/crypto/commitment.rs::commit`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `val`
- Exploit idea: Query `polynomial commitment` repeatedly under attacker-chosen inputs and inspect whether the public output leaks share-dependent structure.
- Invariant to test: Public outputs must not leak hidden share-dependent information about `polynomial commitment` or `serialized scalar`.
- Expected Immunefi impact: Information disclosure of sensitive MPC state
- Fast validation: Construct a deterministic unit or invariant test around `crypto::commitment::commit` that feeds crafted `polynomial commitment` / `serialized scalar` inputs, then assert whether downstream verification accepts an output that should have been rejected.
