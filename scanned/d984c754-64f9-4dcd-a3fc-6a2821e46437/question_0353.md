# Q353: Split global and local checks

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `ecdsa::robust_ecdsa::presign(...)` or `ecdsa::robust_ecdsa::sign(...)` and craft `participants`, `args`, `protocol message timing` so each local sub-check inside `do_presign` accepts its own `presign package` fragment, but the combined global statement over `presign package` is still false and nevertheless accepted, leading to Cryptographic flaws?

## Target
- File/function: `src/ecdsa/robust_ecdsa/presign.rs::do_presign`
- Entrypoint: `ecdsa::robust_ecdsa::presign(...)` or `ecdsa::robust_ecdsa::sign(...)`
- Attacker controls: `participants`, `args`, `protocol message timing`
- Exploit idea: Make each local check over `presign package` pass independently, then verify whether the combined global statement over `presign package` is still false but accepted.
- Invariant to test: Local checks on decomposed subparts of `presign package` must imply the global algebraic statement, not merely independent fragments.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Run two or more local protocol instances around `ecdsa::robust_ecdsa::presign(...)` or `ecdsa::robust_ecdsa::sign(...)`, let one malicious participant inject conflicting, replayed, or cross-context `presign package` data into `do_presign`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
