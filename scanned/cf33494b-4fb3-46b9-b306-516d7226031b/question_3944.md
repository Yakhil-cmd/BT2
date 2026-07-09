# Q3944: Reuse helper output under new signer set

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and carry a previously valid `Lagrange coefficient` helper output into a different participant set or threshold context where `extend_with_zero` still accepts it, leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/crypto/polynomials.rs::extend_with_zero`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `hash output`, `domain-separated hash`
- Exploit idea: Port helper output from one threshold or participant set into another flow that should have rejected it.
- Invariant to test: Helper outputs for `Lagrange coefficient` must be invalid outside their original participant and threshold context.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `crypto::polynomials::extend_with_zero` that feeds crafted `Lagrange coefficient` / `domain-separated hash` inputs, then assert whether downstream verification accepts an output that should have been rejected.
