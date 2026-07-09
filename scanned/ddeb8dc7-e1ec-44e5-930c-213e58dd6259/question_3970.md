# Q3970: Reuse helper output under new signer set

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and carry a previously valid `serialized scalar` helper output into a different participant set or threshold context where `generate_polynomial` still accepts it, leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/crypto/polynomials.rs::generate_polynomial`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `secret`, `degree`
- Exploit idea: Port helper output from one threshold or participant set into another flow that should have rejected it.
- Invariant to test: Helper outputs for `serialized scalar` must be invalid outside their original participant and threshold context.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `crypto::polynomials::generate_polynomial` that feeds crafted `serialized scalar` / `domain-separated hash` inputs, then assert whether downstream verification accepts an output that should have been rejected.
