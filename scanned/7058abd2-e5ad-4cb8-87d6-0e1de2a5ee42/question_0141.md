# Q141: Reuse stale public values

## Question
Can a single malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, or `refresh(...)` and replay an old `commitment hash` or cached `coefficient commitment` into `verify_commitment_hash` after the participant set or transcript changed, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/dkg.rs::verify_commitment_hash`
- Entrypoint: `keygen(...)`, `reshare(...)`, or `refresh(...)`
- Attacker controls: `participant`, `session_id`, `domain_separator`, `commitment`, `protocol message timing`
- Exploit idea: Replay old public data after reshare, refresh, presign, or signer-set changes and see whether it is still consumed.
- Invariant to test: Old `commitment hash` values must become invalid once the participant set or session context changes.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `keygen(...)`, `reshare(...)`, or `refresh(...)`, let one malicious participant inject conflicting, replayed, or cross-context `commitment hash` data into `verify_commitment_hash`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
