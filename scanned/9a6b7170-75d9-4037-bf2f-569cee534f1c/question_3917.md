# Q3917: Desync batched indices

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and use crafted batching inputs in `polynomial commitment`, `Lagrange coefficient` so `extend_with_identity` remaps one party's `interpolation set` to another party's `with` through index, row, or column confusion, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/crypto/polynomials.rs::extend_with_identity`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `polynomial commitment`, `Lagrange coefficient`
- Exploit idea: Exploit array, row, column, or index confusion to remap one participant's `interpolation set` to another.
- Invariant to test: Batched helpers must preserve the original participant-to-`interpolation set` mapping.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `crypto::polynomials::extend_with_identity` that feeds crafted `interpolation set` / `with` inputs, then assert whether downstream verification accepts an output that should have been rejected.
