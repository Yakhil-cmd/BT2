# Q2248: Reuse stale public values

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and replay an old `domain-separated hash` or cached `domain-separated hash` into `commit_polynomial` after the participant set or transcript changed, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/crypto/polynomials.rs::commit_polynomial`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `interpolation set`, `polynomial`
- Exploit idea: Replay old public data after reshare, refresh, presign, or signer-set changes and see whether it is still consumed.
- Invariant to test: Old `domain-separated hash` values must become invalid once the participant set or session context changes.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `crypto::polynomials::commit_polynomial` that feeds crafted `domain-separated hash` / `domain-separated hash` inputs, then assert whether downstream verification accepts an output that should have been rejected.
