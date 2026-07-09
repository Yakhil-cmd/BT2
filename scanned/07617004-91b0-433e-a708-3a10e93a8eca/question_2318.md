# Q2318: Interpolate on malicious subset

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and steer `identifiers`, `shares`, `point` so `eval_interpolation` interpolates `domain-separated hash` over an attacker-influenced subset that is algebraically inconsistent with the honest transcript, leading to Cryptographic flaws?

## Target
- File/function: `src/crypto/polynomials.rs::eval_interpolation`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `identifiers`, `shares`, `point`
- Exploit idea: Force interpolation over attacker-selected indices, then compare the reconstructed `domain-separated hash` against the honest relation.
- Invariant to test: Interpolation must only use the intended threshold-sized honest-consistent subset for `domain-separated hash`.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Construct a deterministic unit or invariant test around `crypto::polynomials::eval_interpolation` that feeds crafted `domain-separated hash` / `interpolation` inputs, then assert whether downstream verification accepts an output that should have been rejected.
