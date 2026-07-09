# Q2420: Interpolate on malicious subset

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and steer `transcript`, `statement`, `proof` so `verify` interpolates `proof encoding` over an attacker-influenced subset that is algebraically inconsistent with the honest transcript, leading to Cryptographic flaws?

## Target
- File/function: `src/crypto/proofs/dlog.rs::verify`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `transcript`, `statement`, `proof`
- Exploit idea: Force interpolation over attacker-selected indices, then compare the reconstructed `proof encoding` against the honest relation.
- Invariant to test: Interpolation must only use the intended threshold-sized honest-consistent subset for `proof encoding`.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Construct a deterministic unit or invariant test around `crypto::proofs::dlog::verify` that feeds crafted `proof encoding` / `proof encoding` inputs, then assert whether downstream verification accepts an output that should have been rejected.
