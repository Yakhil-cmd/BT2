# Q1857: Reuse stale public values

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `confidential_key_derivation::protocol::ckd(...)` and replay an old `app_pk` or cached `encrypted CKD output` into `ckd` after the participant set or transcript changed, causing Unauthorized access to MPC key shares or signing capability?

## Target
- File/function: `src/confidential_key_derivation/protocol.rs::ckd`
- Entrypoint: `confidential_key_derivation::protocol::ckd(...)`
- Attacker controls: `participants`, `coordinator`, `key_pair`, `app_id`, `protocol message timing`
- Exploit idea: Replay old public data after reshare, refresh, presign, or signer-set changes and see whether it is still consumed.
- Invariant to test: Old `app_pk` values must become invalid once the participant set or session context changes.
- Expected Immunefi impact: Unauthorized access to MPC key shares or signing capability
- Fast validation: Run two or more local protocol instances around `confidential_key_derivation::protocol::ckd(...)`, let one malicious participant inject conflicting, replayed, or cross-context `app_pk` data into `ckd`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
