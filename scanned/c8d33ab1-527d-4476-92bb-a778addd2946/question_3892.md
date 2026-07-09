# Q3892: Desync batched indices

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and use crafted batching inputs in `polynomial commitment`, `Lagrange coefficient` so `eval_at_zero` remaps one party's `serialized scalar` to another party's `at` through index, row, or column confusion, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/crypto/polynomials.rs::eval_at_zero`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `polynomial commitment`, `Lagrange coefficient`
- Exploit idea: Exploit array, row, column, or index confusion to remap one participant's `serialized scalar` to another.
- Invariant to test: Batched helpers must preserve the original participant-to-`serialized scalar` mapping.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `crypto::polynomials::eval_at_zero` that feeds crafted `serialized scalar` / `at` inputs, then assert whether downstream verification accepts an output that should have been rejected.
