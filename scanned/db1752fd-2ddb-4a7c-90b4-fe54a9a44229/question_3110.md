# Q3110: Split global and local checks

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `ecdsa::robust_ecdsa::presign(...)` or `ecdsa::robust_ecdsa::sign(...)` and craft `degree`, `protocol message timing` so each local sub-check inside `zero_secret_polynomial` accepts its own `polynomial` fragment, but the combined global statement over `zero` is still false and nevertheless accepted, leading to Cryptographic flaws?

## Target
- File/function: `src/ecdsa/robust_ecdsa/presign.rs::zero_secret_polynomial`
- Entrypoint: `ecdsa::robust_ecdsa::presign(...)` or `ecdsa::robust_ecdsa::sign(...)`
- Attacker controls: `degree`, `protocol message timing`
- Exploit idea: Make each local check over `polynomial` pass independently, then verify whether the combined global statement over `zero` is still false but accepted.
- Invariant to test: Local checks on decomposed subparts of `polynomial` must imply the global algebraic statement, not merely independent fragments.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Run two or more local protocol instances around `ecdsa::robust_ecdsa::presign(...)` or `ecdsa::robust_ecdsa::sign(...)`, let one malicious participant inject conflicting, replayed, or cross-context `polynomial` data into `zero_secret_polynomial`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
