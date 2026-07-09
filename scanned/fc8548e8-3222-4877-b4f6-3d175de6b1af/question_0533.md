# Q533: Split global and local checks

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)` and craft `participants`, `signing_share`, `protocol message timing` so each local sub-check inside `do_presign` accepts its own `signing nonces` fragment, but the combined global statement over `nonce commitment` is still false and nevertheless accepted, leading to Cryptographic flaws?

## Target
- File/function: `src/frost/mod.rs::do_presign`
- Entrypoint: `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)`
- Attacker controls: `participants`, `signing_share`, `protocol message timing`
- Exploit idea: Make each local check over `signing nonces` pass independently, then verify whether the combined global statement over `nonce commitment` is still false but accepted.
- Invariant to test: Local checks on decomposed subparts of `signing nonces` must imply the global algebraic statement, not merely independent fragments.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Run two or more local protocol instances around `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)`, let one malicious participant inject conflicting, replayed, or cross-context `signing nonces` data into `do_presign`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
