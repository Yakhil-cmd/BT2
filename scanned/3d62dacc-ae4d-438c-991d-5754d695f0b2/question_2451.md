# Q2451: Reuse stale public values

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and replay an old `challenge-derived RNG` or cached `generator binding` into `prove_with_nonce` after the participant set or transcript changed, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/crypto/proofs/dlogeq.rs::prove_with_nonce`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `transcript`, `statement`, `witness`, `k`
- Exploit idea: Replay old public data after reshare, refresh, presign, or signer-set changes and see whether it is still consumed.
- Invariant to test: Old `challenge-derived RNG` values must become invalid once the participant set or session context changes.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `crypto::proofs::dlogeq::prove_with_nonce` that feeds crafted `challenge-derived RNG` / `generator binding` inputs, then assert whether downstream verification accepts an output that should have been rejected.
