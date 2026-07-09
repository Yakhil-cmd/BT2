# Q1632: Split global and local checks

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `ecdsa::robust_ecdsa::presign(...)` or `ecdsa::robust_ecdsa::sign(...)` and craft `participants`, `coordinator`, `public_key`, `presignature`, `protocol message timing` so each local sub-check inside `fut_wrapper` accepts its own `fut` fragment, but the combined global statement over `participant set binding` is still false and nevertheless accepted, leading to Cryptographic flaws?

## Target
- File/function: `src/ecdsa/robust_ecdsa/sign.rs::fut_wrapper`
- Entrypoint: `ecdsa::robust_ecdsa::presign(...)` or `ecdsa::robust_ecdsa::sign(...)`
- Attacker controls: `participants`, `coordinator`, `public_key`, `presignature`, `protocol message timing`
- Exploit idea: Make each local check over `fut` pass independently, then verify whether the combined global statement over `participant set binding` is still false but accepted.
- Invariant to test: Local checks on decomposed subparts of `fut` must imply the global algebraic statement, not merely independent fragments.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Run two or more local protocol instances around `ecdsa::robust_ecdsa::presign(...)` or `ecdsa::robust_ecdsa::sign(...)`, let one malicious participant inject conflicting, replayed, or cross-context `fut` data into `fut_wrapper`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
