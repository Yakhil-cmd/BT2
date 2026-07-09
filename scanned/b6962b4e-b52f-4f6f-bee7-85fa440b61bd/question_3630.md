# Q3630: Interpolate on malicious subset

## Question
Can a malicious network peer or malicious coordinator below threshold enter through `Protocol::message(...)` during `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and steer `waitpoint`, `message header`, `protocol message timing` so `root_shared` interpolates `channel tag` over an attacker-influenced subset that is algebraically inconsistent with the honest transcript, leading to Cryptographic flaws?

## Target
- File/function: `src/protocol/internal.rs::root_shared`
- Entrypoint: `Protocol::message(...)` during `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `waitpoint`, `message header`, `protocol message timing`
- Exploit idea: Force interpolation over attacker-selected indices, then compare the reconstructed `channel tag` against the honest relation.
- Invariant to test: Interpolation must only use the intended threshold-sized honest-consistent subset for `channel tag`.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Run two or more local protocol instances around `Protocol::message(...)` during `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`, let one malicious participant inject conflicting, replayed, or cross-context `channel tag` data into `root_shared`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
