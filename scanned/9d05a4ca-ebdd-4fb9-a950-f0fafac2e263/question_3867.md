# Q3867: Desync batched indices

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and use crafted batching inputs in `point` so `eval_at_point` remaps one party's `polynomial commitment` to another party's `serialized group element` through index, row, or column confusion, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/crypto/polynomials.rs::eval_at_point`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `point`
- Exploit idea: Exploit array, row, column, or index confusion to remap one participant's `polynomial commitment` to another.
- Invariant to test: Batched helpers must preserve the original participant-to-`polynomial commitment` mapping.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `crypto::polynomials::eval_at_point` that feeds crafted `polynomial commitment` / `serialized group element` inputs, then assert whether downstream verification accepts an output that should have been rejected.
