# Q520: Interpolate on malicious subset

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)` and steer `participants`, `signing_share`, `protocol message timing` so `do_presign` interpolates `signing nonces` over an attacker-influenced subset that is algebraically inconsistent with the honest transcript, leading to Cryptographic flaws?

## Target
- File/function: `src/frost/mod.rs::do_presign`
- Entrypoint: `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)`
- Attacker controls: `participants`, `signing_share`, `protocol message timing`
- Exploit idea: Force interpolation over attacker-selected indices, then compare the reconstructed `signing nonces` against the honest relation.
- Invariant to test: Interpolation must only use the intended threshold-sized honest-consistent subset for `signing nonces`.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Run two or more local protocol instances around `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)`, let one malicious participant inject conflicting, replayed, or cross-context `signing nonces` data into `do_presign`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
