# Q3605: Interpolate on malicious subset

## Question
Can a malicious network peer or malicious coordinator below threshold enter through `Protocol::message(...)` during `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and steer `p0`, `p1`, `protocol message timing` so `root_private` interpolates `round message` over an attacker-influenced subset that is algebraically inconsistent with the honest transcript, leading to Cryptographic flaws?

## Target
- File/function: `src/protocol/internal.rs::root_private`
- Entrypoint: `Protocol::message(...)` during `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `p0`, `p1`, `protocol message timing`
- Exploit idea: Force interpolation over attacker-selected indices, then compare the reconstructed `round message` against the honest relation.
- Invariant to test: Interpolation must only use the intended threshold-sized honest-consistent subset for `round message`.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Run two or more local protocol instances around `Protocol::message(...)` during `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`, let one malicious participant inject conflicting, replayed, or cross-context `round message` data into `root_private`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
