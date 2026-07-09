# Q3960: Interpolate on malicious subset

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and steer `secret`, `degree` so `generate_polynomial` interpolates `interpolation set` over an attacker-influenced subset that is algebraically inconsistent with the honest transcript, leading to Cryptographic flaws?

## Target
- File/function: `src/crypto/polynomials.rs::generate_polynomial`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `secret`, `degree`
- Exploit idea: Force interpolation over attacker-selected indices, then compare the reconstructed `interpolation set` against the honest relation.
- Invariant to test: Interpolation must only use the intended threshold-sized honest-consistent subset for `interpolation set`.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Construct a deterministic unit or invariant test around `crypto::polynomials::generate_polynomial` that feeds crafted `interpolation set` / `Lagrange coefficient` inputs, then assert whether downstream verification accepts an output that should have been rejected.
