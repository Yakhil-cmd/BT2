# Q2150: Leak sensitive state through output

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and choose `domain_separator`, `data` so repeated calls to `domain_separate_hash` expose share-dependent structure in `serialized scalar` or `hash output` that should stay hidden, causing Information disclosure of sensitive MPC state?

## Target
- File/function: `src/crypto/hash.rs::domain_separate_hash`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `domain_separator`, `data`
- Exploit idea: Query `serialized scalar` repeatedly under attacker-chosen inputs and inspect whether the public output leaks share-dependent structure.
- Invariant to test: Public outputs must not leak hidden share-dependent information about `serialized scalar` or `hash output`.
- Expected Immunefi impact: Information disclosure of sensitive MPC state
- Fast validation: Construct a deterministic unit or invariant test around `crypto::hash::domain_separate_hash` that feeds crafted `serialized scalar` / `hash output` inputs, then assert whether downstream verification accepts an output that should have been rejected.
