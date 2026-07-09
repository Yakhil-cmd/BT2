# Q2036: Interpolate on malicious subset

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)` and steer `participants`, `coordinator`, `threshold`, `protocol message timing` so `assert_sign_inputs` interpolates `nonce commitment` over an attacker-influenced subset that is algebraically inconsistent with the honest transcript, leading to Cryptographic flaws?

## Target
- File/function: `src/frost/mod.rs::assert_sign_inputs`
- Entrypoint: `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)`
- Attacker controls: `participants`, `coordinator`, `threshold`, `protocol message timing`
- Exploit idea: Force interpolation over attacker-selected indices, then compare the reconstructed `nonce commitment` against the honest relation.
- Invariant to test: Interpolation must only use the intended threshold-sized honest-consistent subset for `nonce commitment`.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Run two or more local protocol instances around `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)`, let one malicious participant inject conflicting, replayed, or cross-context `nonce commitment` data into `assert_sign_inputs`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
