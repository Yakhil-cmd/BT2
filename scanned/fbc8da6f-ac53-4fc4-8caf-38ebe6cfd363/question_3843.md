# Q3843: Reuse helper output under new signer set

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and carry a previously valid `polynomial commitment` helper output into a different participant set or threshold context where `eval_at_participant` still accepts it, leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/crypto/polynomials.rs::eval_at_participant`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `participant`
- Exploit idea: Port helper output from one threshold or participant set into another flow that should have rejected it.
- Invariant to test: Helper outputs for `polynomial commitment` must be invalid outside their original participant and threshold context.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `crypto::polynomials::eval_at_participant` that feeds crafted `polynomial commitment` / `Lagrange coefficient` inputs, then assert whether downstream verification accepts an output that should have been rejected.
