# Q109: Interpolate on malicious subset

## Question
Can a single malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, or `refresh(...)` and steer `participants`, `threshold`, `old_participants`, `old_public_key`, `protocol message timing` so `do_reshare` interpolates `old participant set` over an attacker-influenced subset that is algebraically inconsistent with the honest transcript, leading to Cryptographic flaws?

## Target
- File/function: `src/dkg.rs::do_reshare`
- Entrypoint: `keygen(...)`, `reshare(...)`, or `refresh(...)`
- Attacker controls: `participants`, `threshold`, `old_participants`, `old_public_key`, `protocol message timing`
- Exploit idea: Force interpolation over attacker-selected indices, then compare the reconstructed `old participant set` against the honest relation.
- Invariant to test: Interpolation must only use the intended threshold-sized honest-consistent subset for `old participant set`.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Run two or more local protocol instances around `keygen(...)`, `reshare(...)`, or `refresh(...)`, let one malicious participant inject conflicting, replayed, or cross-context `old participant set` data into `do_reshare`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
