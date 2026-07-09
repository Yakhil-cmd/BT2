# Q815: Split global and local checks

## Question
Can a malicious network peer or malicious coordinator below threshold enter through `Protocol::message(...)` during `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and craft `participants`, `wait`, `data`, `protocol message timing` so each local sub-check inside `reliable_broadcast_send` accepts its own `round message` fragment, but the combined global statement over `reliable` is still false and nevertheless accepted, leading to Cryptographic flaws?

## Target
- File/function: `src/protocol/echo_broadcast.rs::reliable_broadcast_send`
- Entrypoint: `Protocol::message(...)` during `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `participants`, `wait`, `data`, `protocol message timing`
- Exploit idea: Make each local check over `round message` pass independently, then verify whether the combined global statement over `reliable` is still false but accepted.
- Invariant to test: Local checks on decomposed subparts of `round message` must imply the global algebraic statement, not merely independent fragments.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Run two or more local protocol instances around `Protocol::message(...)` during `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`, let one malicious participant inject conflicting, replayed, or cross-context `round message` data into `reliable_broadcast_send`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
