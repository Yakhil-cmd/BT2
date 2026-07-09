# Q2072: Leak sensitive state through output

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and choose `val`, `r` so repeated calls to `check` expose share-dependent structure in `domain-separated hash` or `Lagrange coefficient` that should stay hidden, causing Information disclosure of sensitive MPC state?

## Target
- File/function: `src/crypto/commitment.rs::check`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `val`, `r`
- Exploit idea: Query `domain-separated hash` repeatedly under attacker-chosen inputs and inspect whether the public output leaks share-dependent structure.
- Invariant to test: Public outputs must not leak hidden share-dependent information about `domain-separated hash` or `Lagrange coefficient`.
- Expected Immunefi impact: Information disclosure of sensitive MPC state
- Fast validation: Construct a deterministic unit or invariant test around `crypto::commitment::check` that feeds crafted `domain-separated hash` / `Lagrange coefficient` inputs, then assert whether downstream verification accepts an output that should have been rejected.
