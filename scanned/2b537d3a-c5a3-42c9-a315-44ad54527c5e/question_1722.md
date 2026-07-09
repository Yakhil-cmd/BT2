# Q1722: Interpolate on malicious subset

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `frost::eddsa::sign::sign_v2(...)` and steer `participants`, `coordinator`, `threshold`, `presignature`, `protocol message timing` so `sign_v2` interpolates `coordinator-selected signer set` over an attacker-influenced subset that is algebraically inconsistent with the honest transcript, leading to Cryptographic flaws?

## Target
- File/function: `src/frost/eddsa/sign.rs::sign_v2`
- Entrypoint: `frost::eddsa::sign::sign_v2(...)`
- Attacker controls: `participants`, `coordinator`, `threshold`, `presignature`, `protocol message timing`
- Exploit idea: Force interpolation over attacker-selected indices, then compare the reconstructed `coordinator-selected signer set` against the honest relation.
- Invariant to test: Interpolation must only use the intended threshold-sized honest-consistent subset for `coordinator-selected signer set`.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Run two or more local protocol instances around `frost::eddsa::sign::sign_v2(...)`, let one malicious participant inject conflicting, replayed, or cross-context `coordinator-selected signer set` data into `sign_v2`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
