# Q3643: Split global and local checks

## Question
Can a malicious network peer or malicious coordinator below threshold enter through `Protocol::message(...)` during `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and craft `round message`, `channel tag`, `protocol message timing` so each local sub-check inside `root_shared` accepts its own `shared` fragment, but the combined global statement over `private channel` is still false and nevertheless accepted, leading to Cryptographic flaws?

## Target
- File/function: `src/protocol/internal.rs::root_shared`
- Entrypoint: `Protocol::message(...)` during `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `round message`, `channel tag`, `protocol message timing`
- Exploit idea: Make each local check over `shared` pass independently, then verify whether the combined global statement over `private channel` is still false but accepted.
- Invariant to test: Local checks on decomposed subparts of `shared` must imply the global algebraic statement, not merely independent fragments.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Run two or more local protocol instances around `Protocol::message(...)` during `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`, let one malicious participant inject conflicting, replayed, or cross-context `shared` data into `root_shared`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
