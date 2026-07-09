# Q2113: Interpolate on malicious subset

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and steer `val`, `r` so `compute` interpolates `serialized scalar` over an attacker-influenced subset that is algebraically inconsistent with the honest transcript, leading to Cryptographic flaws?

## Target
- File/function: `src/crypto/commitment.rs::compute`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `val`, `r`
- Exploit idea: Force interpolation over attacker-selected indices, then compare the reconstructed `serialized scalar` against the honest relation.
- Invariant to test: Interpolation must only use the intended threshold-sized honest-consistent subset for `serialized scalar`.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Construct a deterministic unit or invariant test around `crypto::commitment::compute` that feeds crafted `serialized scalar` / `serialized group element` inputs, then assert whether downstream verification accepts an output that should have been rejected.
