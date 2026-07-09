# Q2319: Omit context from rerandomization

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and exploit `eval_interpolation` so `Lagrange coefficient` is not fully bound to message, participant set, transcript, or presign context, enabling Bypass of threshold signature requirements?

## Target
- File/function: `src/crypto/polynomials.rs::eval_interpolation`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `identifiers`, `shares`, `point`
- Exploit idea: Change message, signer set, or transcript context while reusing the same `Lagrange coefficient` helper material.
- Invariant to test: Derived or rerandomized `Lagrange coefficient` outputs must be bound to message, signer set, and transcript context.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `crypto::polynomials::eval_interpolation` that feeds crafted `Lagrange coefficient` / `interpolation set` inputs, then assert whether downstream verification accepts an output that should have been rejected.
