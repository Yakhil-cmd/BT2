# Q2375: Reuse stale public values

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and replay an old `interpolation set` or cached `domain-separated hash` into `verify` after the participant set or transcript changed, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/ecdsa/mod.rs::verify`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `public_key`, `msg_hash`
- Exploit idea: Replay old public data after reshare, refresh, presign, or signer-set changes and see whether it is still consumed.
- Invariant to test: Old `interpolation set` values must become invalid once the participant set or session context changes.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `ecdsa::verify` that feeds crafted `interpolation set` / `domain-separated hash` inputs, then assert whether downstream verification accepts an output that should have been rejected.
