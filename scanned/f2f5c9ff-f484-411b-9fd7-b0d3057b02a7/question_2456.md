# Q2456: Leak sensitive state through output

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and choose `transcript`, `statement`, `witness`, `k` so repeated calls to `prove_with_nonce` expose share-dependent structure in `nonce` or `generator binding` that should stay hidden, causing Information disclosure of sensitive MPC state?

## Target
- File/function: `src/crypto/proofs/dlogeq.rs::prove_with_nonce`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `transcript`, `statement`, `witness`, `k`
- Exploit idea: Query `nonce` repeatedly under attacker-chosen inputs and inspect whether the public output leaks share-dependent structure.
- Invariant to test: Public outputs must not leak hidden share-dependent information about `nonce` or `generator binding`.
- Expected Immunefi impact: Information disclosure of sensitive MPC state
- Fast validation: Construct a deterministic unit or invariant test around `crypto::proofs::dlogeq::prove_with_nonce` that feeds crafted `nonce` / `generator binding` inputs, then assert whether downstream verification accepts an output that should have been rejected.
