# Q3384: Reuse stale public values

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `confidential_key_derivation::ckd(...)` and replay an old `app_id` or cached `hash_app_id_with_pk binding` into `invert` after the participant set or transcript changed, causing Unauthorized access to MPC key shares or signing capability?

## Target
- File/function: `src/confidential_key_derivation/ciphersuite.rs::invert`
- Entrypoint: `confidential_key_derivation::ckd(...)`
- Attacker controls: `scalar`, `Self`, `protocol message timing`
- Exploit idea: Replay old public data after reshare, refresh, presign, or signer-set changes and see whether it is still consumed.
- Invariant to test: Old `app_id` values must become invalid once the participant set or session context changes.
- Expected Immunefi impact: Unauthorized access to MPC key shares or signing capability
- Fast validation: Run two or more local protocol instances around `confidential_key_derivation::ckd(...)`, let one malicious participant inject conflicting, replayed, or cross-context `app_id` data into `invert`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
