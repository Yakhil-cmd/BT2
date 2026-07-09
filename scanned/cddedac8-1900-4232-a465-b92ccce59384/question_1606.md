# Q1606: Split global and local checks

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `ecdsa::robust_ecdsa::presign(...)` or `ecdsa::robust_ecdsa::sign(...)` and craft `participants`, `presignature`, `msg_hash`, `protocol message timing` so each local sub-check inside `compute_signature_share` accepts its own `max_malicious bound` fragment, but the combined global statement over `max_malicious bound` is still false and nevertheless accepted, leading to Cryptographic flaws?

## Target
- File/function: `src/ecdsa/robust_ecdsa/sign.rs::compute_signature_share`
- Entrypoint: `ecdsa::robust_ecdsa::presign(...)` or `ecdsa::robust_ecdsa::sign(...)`
- Attacker controls: `participants`, `presignature`, `msg_hash`, `protocol message timing`
- Exploit idea: Make each local check over `max_malicious bound` pass independently, then verify whether the combined global statement over `max_malicious bound` is still false but accepted.
- Invariant to test: Local checks on decomposed subparts of `max_malicious bound` must imply the global algebraic statement, not merely independent fragments.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Run two or more local protocol instances around `ecdsa::robust_ecdsa::presign(...)` or `ecdsa::robust_ecdsa::sign(...)`, let one malicious participant inject conflicting, replayed, or cross-context `max_malicious bound` data into `compute_signature_share`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
