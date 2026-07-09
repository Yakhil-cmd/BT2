# Q1581: Split global and local checks

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `ecdsa::robust_ecdsa::presign::presign(...)` and craft `participants`, `args`, `protocol message timing` so each local sub-check inside `presign` accepts its own `presign` fragment, but the combined global statement over `big_r share` is still false and nevertheless accepted, leading to Cryptographic flaws?

## Target
- File/function: `src/ecdsa/robust_ecdsa/presign.rs::presign`
- Entrypoint: `ecdsa::robust_ecdsa::presign::presign(...)`
- Attacker controls: `participants`, `args`, `protocol message timing`
- Exploit idea: Make each local check over `presign` pass independently, then verify whether the combined global statement over `big_r share` is still false but accepted.
- Invariant to test: Local checks on decomposed subparts of `presign` must imply the global algebraic statement, not merely independent fragments.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Run two or more local protocol instances around `ecdsa::robust_ecdsa::presign::presign(...)`, let one malicious participant inject conflicting, replayed, or cross-context `presign` data into `presign`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
