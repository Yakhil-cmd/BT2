# Q1831: Reuse stale public values

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `frost::redjubjub::sign::sign(...)` and replay an old `presignature context` or cached `commitments_map` into `sign` after the participant set or transcript changed, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/frost/redjubjub/sign.rs::sign`
- Entrypoint: `frost::redjubjub::sign::sign(...)`
- Attacker controls: `participants`, `coordinator`, `threshold`, `presignature`, `protocol message timing`
- Exploit idea: Replay old public data after reshare, refresh, presign, or signer-set changes and see whether it is still consumed.
- Invariant to test: Old `presignature context` values must become invalid once the participant set or session context changes.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `frost::redjubjub::sign::sign(...)`, let one malicious participant inject conflicting, replayed, or cross-context `presignature context` data into `sign`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
