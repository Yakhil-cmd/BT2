# Q1838: Split global and local checks

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `frost::redjubjub::sign::sign(...)` and craft `participants`, `coordinator`, `threshold`, `presignature`, `protocol message timing` so each local sub-check inside `sign` accepts its own `commitments_map` fragment, but the combined global statement over `signing nonces` is still false and nevertheless accepted, leading to Cryptographic flaws?

## Target
- File/function: `src/frost/redjubjub/sign.rs::sign`
- Entrypoint: `frost::redjubjub::sign::sign(...)`
- Attacker controls: `participants`, `coordinator`, `threshold`, `presignature`, `protocol message timing`
- Exploit idea: Make each local check over `commitments_map` pass independently, then verify whether the combined global statement over `signing nonces` is still false but accepted.
- Invariant to test: Local checks on decomposed subparts of `commitments_map` must imply the global algebraic statement, not merely independent fragments.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Run two or more local protocol instances around `frost::redjubjub::sign::sign(...)`, let one malicious participant inject conflicting, replayed, or cross-context `commitments_map` data into `sign`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
