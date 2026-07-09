# Q379: Split global and local checks

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `ecdsa::robust_ecdsa::presign(...)` or `ecdsa::robust_ecdsa::sign(...)` and craft `participants`, `public_key`, `presignature`, `msg_hash`, `protocol message timing` so each local sub-check inside `do_sign_coordinator` accepts its own `participant set binding` fragment, but the combined global statement over `w share` is still false and nevertheless accepted, leading to Cryptographic flaws?

## Target
- File/function: `src/ecdsa/robust_ecdsa/sign.rs::do_sign_coordinator`
- Entrypoint: `ecdsa::robust_ecdsa::presign(...)` or `ecdsa::robust_ecdsa::sign(...)`
- Attacker controls: `participants`, `public_key`, `presignature`, `msg_hash`, `protocol message timing`
- Exploit idea: Make each local check over `participant set binding` pass independently, then verify whether the combined global statement over `w share` is still false but accepted.
- Invariant to test: Local checks on decomposed subparts of `participant set binding` must imply the global algebraic statement, not merely independent fragments.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Run two or more local protocol instances around `ecdsa::robust_ecdsa::presign(...)` or `ecdsa::robust_ecdsa::sign(...)`, let one malicious participant inject conflicting, replayed, or cross-context `participant set binding` data into `do_sign_coordinator`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
