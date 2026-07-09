# Q2097: Reuse helper output under new signer set

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and carry a previously valid `polynomial` helper output into a different participant set or threshold context where `commit` still accepts it, leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/crypto/commitment.rs::commit`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `val`
- Exploit idea: Port helper output from one threshold or participant set into another flow that should have rejected it.
- Invariant to test: Helper outputs for `polynomial` must be invalid outside their original participant and threshold context.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `crypto::commitment::commit` that feeds crafted `polynomial` / `serialized group element` inputs, then assert whether downstream verification accepts an output that should have been rejected.
