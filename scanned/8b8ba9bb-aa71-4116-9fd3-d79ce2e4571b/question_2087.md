# Q2087: Interpolate on malicious subset

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and steer `val` so `commit` interpolates `serialized group element` over an attacker-influenced subset that is algebraically inconsistent with the honest transcript, leading to Cryptographic flaws?

## Target
- File/function: `src/crypto/commitment.rs::commit`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `val`
- Exploit idea: Force interpolation over attacker-selected indices, then compare the reconstructed `serialized group element` against the honest relation.
- Invariant to test: Interpolation must only use the intended threshold-sized honest-consistent subset for `serialized group element`.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Construct a deterministic unit or invariant test around `crypto::commitment::commit` that feeds crafted `serialized group element` / `hash output` inputs, then assert whether downstream verification accepts an output that should have been rejected.
