# Q2114: Omit context from rerandomization

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and exploit `compute` so `serialized scalar` is not fully bound to message, participant set, transcript, or presign context, enabling Bypass of threshold signature requirements?

## Target
- File/function: `src/crypto/commitment.rs::compute`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `val`, `r`
- Exploit idea: Change message, signer set, or transcript context while reusing the same `serialized scalar` helper material.
- Invariant to test: Derived or rerandomized `serialized scalar` outputs must be bound to message, signer set, and transcript context.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `crypto::commitment::compute` that feeds crafted `serialized scalar` / `polynomial commitment` inputs, then assert whether downstream verification accepts an output that should have been rejected.
