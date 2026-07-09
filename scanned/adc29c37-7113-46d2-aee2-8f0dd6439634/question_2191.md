# Q2191: Omit context from rerandomization

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and exploit `batch_compute_lagrange_coefficients` so `serialized scalar` is not fully bound to message, participant set, transcript, or presign context, enabling Bypass of threshold signature requirements?

## Target
- File/function: `src/crypto/polynomials.rs::batch_compute_lagrange_coefficients`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `points_set`, `x`
- Exploit idea: Change message, signer set, or transcript context while reusing the same `serialized scalar` helper material.
- Invariant to test: Derived or rerandomized `serialized scalar` outputs must be bound to message, signer set, and transcript context.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `crypto::polynomials::batch_compute_lagrange_coefficients` that feeds crafted `serialized scalar` / `interpolation set` inputs, then assert whether downstream verification accepts an output that should have been rejected.
