# Q2677: Reuse stale public values

## Question
Can a single malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, or `refresh(...)` and replay an old `proof of knowledge` or cached `session_id` into `internal_verify_proof_of_knowledge` after the participant set or transcript changed, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/dkg.rs::internal_verify_proof_of_knowledge`
- Entrypoint: `keygen(...)`, `reshare(...)`, or `refresh(...)`
- Attacker controls: `participant`, `session_id`, `domain_separator`, `commitment`, `protocol message timing`
- Exploit idea: Replay old public data after reshare, refresh, presign, or signer-set changes and see whether it is still consumed.
- Invariant to test: Old `proof of knowledge` values must become invalid once the participant set or session context changes.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `keygen(...)`, `reshare(...)`, or `refresh(...)`, let one malicious participant inject conflicting, replayed, or cross-context `proof of knowledge` data into `internal_verify_proof_of_knowledge`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
