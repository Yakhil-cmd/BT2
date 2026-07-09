# Q1574: Reuse stale public values

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `ecdsa::robust_ecdsa::presign::presign(...)` and replay an old `big_r share` or cached `max_malicious bound` into `presign` after the participant set or transcript changed, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/ecdsa/robust_ecdsa/presign.rs::presign`
- Entrypoint: `ecdsa::robust_ecdsa::presign::presign(...)`
- Attacker controls: `participants`, `args`, `protocol message timing`
- Exploit idea: Replay old public data after reshare, refresh, presign, or signer-set changes and see whether it is still consumed.
- Invariant to test: Old `big_r share` values must become invalid once the participant set or session context changes.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `ecdsa::robust_ecdsa::presign::presign(...)`, let one malicious participant inject conflicting, replayed, or cross-context `big_r share` data into `presign`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
