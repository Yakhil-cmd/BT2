# Q3818: Leak sensitive state through output

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and choose `deserializer` so repeated calls to `deserialize` expose share-dependent structure in `polynomial` or `deserialize` that should stay hidden, causing Information disclosure of sensitive MPC state?

## Target
- File/function: `src/crypto/polynomials.rs::deserialize`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `deserializer`
- Exploit idea: Query `polynomial` repeatedly under attacker-chosen inputs and inspect whether the public output leaks share-dependent structure.
- Invariant to test: Public outputs must not leak hidden share-dependent information about `polynomial` or `deserialize`.
- Expected Immunefi impact: Information disclosure of sensitive MPC state
- Fast validation: Construct a deterministic unit or invariant test around `crypto::polynomials::deserialize` that feeds crafted `polynomial` / `deserialize` inputs, then assert whether downstream verification accepts an output that should have been rejected.
