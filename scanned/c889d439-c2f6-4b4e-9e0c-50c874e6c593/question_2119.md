# Q2119: Reuse stale public values

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and replay an old `polynomial` or cached `polynomial commitment` into `compute` after the participant set or transcript changed, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/crypto/commitment.rs::compute`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `val`, `r`
- Exploit idea: Replay old public data after reshare, refresh, presign, or signer-set changes and see whether it is still consumed.
- Invariant to test: Old `polynomial` values must become invalid once the participant set or session context changes.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `crypto::commitment::compute` that feeds crafted `polynomial` / `polynomial commitment` inputs, then assert whether downstream verification accepts an output that should have been rejected.
