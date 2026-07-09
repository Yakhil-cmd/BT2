# Q2479: Leak sensitive state through output

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and choose `transcript`, `statement`, `proof` so repeated calls to `verify` expose share-dependent structure in `challenge-derived RNG` or `generator binding` that should stay hidden, causing Information disclosure of sensitive MPC state?

## Target
- File/function: `src/crypto/proofs/dlogeq.rs::verify`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `transcript`, `statement`, `proof`
- Exploit idea: Query `challenge-derived RNG` repeatedly under attacker-chosen inputs and inspect whether the public output leaks share-dependent structure.
- Invariant to test: Public outputs must not leak hidden share-dependent information about `challenge-derived RNG` or `generator binding`.
- Expected Immunefi impact: Information disclosure of sensitive MPC state
- Fast validation: Construct a deterministic unit or invariant test around `crypto::proofs::dlogeq::verify` that feeds crafted `challenge-derived RNG` / `generator binding` inputs, then assert whether downstream verification accepts an output that should have been rejected.
