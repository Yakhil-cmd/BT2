# Q841: Split global and local checks

## Question
Can a malicious network peer or malicious coordinator below threshold enter through `Protocol::message(...)` during `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and craft `participants`, `waitpoint`, `protocol message timing` so each local sub-check inside `recv_from_others` accepts its own `waitpoint` fragment, but the combined global statement over `message buffer` is still false and nevertheless accepted, leading to Cryptographic flaws?

## Target
- File/function: `src/protocol/helpers.rs::recv_from_others`
- Entrypoint: `Protocol::message(...)` during `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `participants`, `waitpoint`, `protocol message timing`
- Exploit idea: Make each local check over `waitpoint` pass independently, then verify whether the combined global statement over `message buffer` is still false but accepted.
- Invariant to test: Local checks on decomposed subparts of `waitpoint` must imply the global algebraic statement, not merely independent fragments.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Run two or more local protocol instances around `Protocol::message(...)` during `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`, let one malicious participant inject conflicting, replayed, or cross-context `waitpoint` data into `recv_from_others`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
