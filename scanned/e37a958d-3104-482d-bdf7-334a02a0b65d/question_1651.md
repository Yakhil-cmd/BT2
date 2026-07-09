# Q1651: Reuse stale public values

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `ecdsa::robust_ecdsa::sign::sign(...)` and replay an old `presign package` or cached `big_r share` into `sign` after the participant set or transcript changed, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/ecdsa/robust_ecdsa/sign.rs::sign`
- Entrypoint: `ecdsa::robust_ecdsa::sign::sign(...)`
- Attacker controls: `participants`, `coordinator`, `max_malicious`, `public_key`, `protocol message timing`
- Exploit idea: Replay old public data after reshare, refresh, presign, or signer-set changes and see whether it is still consumed.
- Invariant to test: Old `presign package` values must become invalid once the participant set or session context changes.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `ecdsa::robust_ecdsa::sign::sign(...)`, let one malicious participant inject conflicting, replayed, or cross-context `presign package` data into `sign`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
