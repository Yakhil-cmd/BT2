# Q2710: Split global and local checks

## Question
Can a malicious network peer or malicious coordinator below threshold enter through `Protocol::message(...)` during `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and craft `n`, `protocol message timing` so each local sub-check inside `echo_ready_thresholds` accepts its own `message header` fragment, but the combined global statement over `ready` is still false and nevertheless accepted, leading to Cryptographic flaws?

## Target
- File/function: `src/protocol/echo_broadcast.rs::echo_ready_thresholds`
- Entrypoint: `Protocol::message(...)` during `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `n`, `protocol message timing`
- Exploit idea: Make each local check over `message header` pass independently, then verify whether the combined global statement over `ready` is still false but accepted.
- Invariant to test: Local checks on decomposed subparts of `message header` must imply the global algebraic statement, not merely independent fragments.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Run two or more local protocol instances around `Protocol::message(...)` during `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`, let one malicious participant inject conflicting, replayed, or cross-context `message header` data into `echo_ready_thresholds`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
