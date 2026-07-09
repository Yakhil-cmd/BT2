# Q3555: Interpolate on malicious subset

## Question
Can a malicious network peer or malicious coordinator below threshold enter through `Protocol::message(...)` during `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and steer `waitpoint`, `message header`, `protocol message timing` so `outgoing` interpolates `round message` over an attacker-influenced subset that is algebraically inconsistent with the honest transcript, leading to Cryptographic flaws?

## Target
- File/function: `src/protocol/internal.rs::outgoing`
- Entrypoint: `Protocol::message(...)` during `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `waitpoint`, `message header`, `protocol message timing`
- Exploit idea: Force interpolation over attacker-selected indices, then compare the reconstructed `round message` against the honest relation.
- Invariant to test: Interpolation must only use the intended threshold-sized honest-consistent subset for `round message`.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Run two or more local protocol instances around `Protocol::message(...)` during `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`, let one malicious participant inject conflicting, replayed, or cross-context `round message` data into `outgoing`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
