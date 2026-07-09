# Q1702: Reuse stale public values

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `frost::eddsa::sign::sign_v1(...)` and replay an old `nonce commitment` or cached `commitments_map` into `sign_v1` after the participant set or transcript changed, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/frost/eddsa/sign.rs::sign_v1`
- Entrypoint: `frost::eddsa::sign::sign_v1(...)`
- Attacker controls: `participants`, `coordinator`, `threshold`, `keygen_output`, `protocol message timing`
- Exploit idea: Replay old public data after reshare, refresh, presign, or signer-set changes and see whether it is still consumed.
- Invariant to test: Old `nonce commitment` values must become invalid once the participant set or session context changes.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `frost::eddsa::sign::sign_v1(...)`, let one malicious participant inject conflicting, replayed, or cross-context `nonce commitment` data into `sign_v1`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
