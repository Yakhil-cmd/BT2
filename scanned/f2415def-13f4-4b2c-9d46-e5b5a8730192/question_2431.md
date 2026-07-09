# Q2431: Leak sensitive state through output

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and choose `transcript`, `statement`, `proof` so repeated calls to `verify` expose share-dependent structure in `generator binding` or `transcript state` that should stay hidden, causing Information disclosure of sensitive MPC state?

## Target
- File/function: `src/crypto/proofs/dlog.rs::verify`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `transcript`, `statement`, `proof`
- Exploit idea: Query `generator binding` repeatedly under attacker-chosen inputs and inspect whether the public output leaks share-dependent structure.
- Invariant to test: Public outputs must not leak hidden share-dependent information about `generator binding` or `transcript state`.
- Expected Immunefi impact: Information disclosure of sensitive MPC state
- Fast validation: Construct a deterministic unit or invariant test around `crypto::proofs::dlog::verify` that feeds crafted `generator binding` / `transcript state` inputs, then assert whether downstream verification accepts an output that should have been rejected.
