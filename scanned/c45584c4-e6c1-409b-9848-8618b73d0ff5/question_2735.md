# Q2735: Split global and local checks

## Question
Can a malicious network peer or malicious coordinator below threshold enter through `Protocol::message(...)` during `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and craft `i`, `protocol message timing` so each local sub-check inside `child` accepts its own `private channel` fragment, but the combined global statement over `child channel` is still false and nevertheless accepted, leading to Cryptographic flaws?

## Target
- File/function: `src/protocol/internal.rs::child`
- Entrypoint: `Protocol::message(...)` during `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `i`, `protocol message timing`
- Exploit idea: Make each local check over `private channel` pass independently, then verify whether the combined global statement over `child channel` is still false but accepted.
- Invariant to test: Local checks on decomposed subparts of `private channel` must imply the global algebraic statement, not merely independent fragments.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Run two or more local protocol instances around `Protocol::message(...)` during `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`, let one malicious participant inject conflicting, replayed, or cross-context `private channel` data into `child`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
