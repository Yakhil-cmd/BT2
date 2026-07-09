# Q57: Interpolate on malicious subset

## Question
Can a single malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, or `refresh(...)` and steer `participants`, `threshold`, `protocol message timing` so `do_keygen` interpolates `commitment hash` over an attacker-influenced subset that is algebraically inconsistent with the honest transcript, leading to Cryptographic flaws?

## Target
- File/function: `src/dkg.rs::do_keygen`
- Entrypoint: `keygen(...)`, `reshare(...)`, or `refresh(...)`
- Attacker controls: `participants`, `threshold`, `protocol message timing`
- Exploit idea: Force interpolation over attacker-selected indices, then compare the reconstructed `commitment hash` against the honest relation.
- Invariant to test: Interpolation must only use the intended threshold-sized honest-consistent subset for `commitment hash`.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Run two or more local protocol instances around `keygen(...)`, `reshare(...)`, or `refresh(...)`, let one malicious participant inject conflicting, replayed, or cross-context `commitment hash` data into `do_keygen`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
