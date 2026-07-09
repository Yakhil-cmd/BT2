# Q1761: Split global and local checks

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `frost::presign(...)` and craft `participants`, `args`, `protocol message timing` so each local sub-check inside `presign` accepts its own `key package` fragment, but the combined global statement over `nonce commitment` is still false and nevertheless accepted, leading to Cryptographic flaws?

## Target
- File/function: `src/frost/mod.rs::presign`
- Entrypoint: `frost::presign(...)`
- Attacker controls: `participants`, `args`, `protocol message timing`
- Exploit idea: Make each local check over `key package` pass independently, then verify whether the combined global statement over `nonce commitment` is still false but accepted.
- Invariant to test: Local checks on decomposed subparts of `key package` must imply the global algebraic statement, not merely independent fragments.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Run two or more local protocol instances around `frost::presign(...)`, let one malicious participant inject conflicting, replayed, or cross-context `key package` data into `presign`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
