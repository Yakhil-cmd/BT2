# Q603: Reuse stale public values

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `confidential_key_derivation::ciphersuite::verify_signature(...)` and replay an old `scalar wrapper` or cached `app_pk` into `verify_signature` after the participant set or transcript changed, causing Unauthorized access to MPC key shares or signing capability?

## Target
- File/function: `src/confidential_key_derivation/ciphersuite.rs::verify_signature`
- Entrypoint: `confidential_key_derivation::ciphersuite::verify_signature(...)`
- Attacker controls: `verifying_key`, `msg`, `signature`, `protocol message timing`
- Exploit idea: Replay old public data after reshare, refresh, presign, or signer-set changes and see whether it is still consumed.
- Invariant to test: Old `scalar wrapper` values must become invalid once the participant set or session context changes.
- Expected Immunefi impact: Unauthorized access to MPC key shares or signing capability
- Fast validation: Run two or more local protocol instances around `confidential_key_derivation::ciphersuite::verify_signature(...)`, let one malicious participant inject conflicting, replayed, or cross-context `scalar wrapper` data into `verify_signature`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
