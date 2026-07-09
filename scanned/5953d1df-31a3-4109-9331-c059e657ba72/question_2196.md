# Q2196: Reuse stale public values

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and replay an old `polynomial commitment` or cached `serialized scalar` into `batch_compute_lagrange_coefficients` after the participant set or transcript changed, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/crypto/polynomials.rs::batch_compute_lagrange_coefficients`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `points_set`, `x`
- Exploit idea: Replay old public data after reshare, refresh, presign, or signer-set changes and see whether it is still consumed.
- Invariant to test: Old `polynomial commitment` values must become invalid once the participant set or session context changes.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `crypto::polynomials::batch_compute_lagrange_coefficients` that feeds crafted `polynomial commitment` / `serialized scalar` inputs, then assert whether downstream verification accepts an output that should have been rejected.
