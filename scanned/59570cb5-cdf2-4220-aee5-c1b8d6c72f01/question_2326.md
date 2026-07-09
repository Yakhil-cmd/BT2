# Q2326: Desync batched indices

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and use crafted batching inputs in `identifiers`, `shares`, `point` so `eval_interpolation` remaps one party's `interpolation` to another party's `polynomial commitment` through index, row, or column confusion, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/crypto/polynomials.rs::eval_interpolation`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `identifiers`, `shares`, `point`
- Exploit idea: Exploit array, row, column, or index confusion to remap one participant's `interpolation` to another.
- Invariant to test: Batched helpers must preserve the original participant-to-`interpolation` mapping.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `crypto::polynomials::eval_interpolation` that feeds crafted `interpolation` / `polynomial commitment` inputs, then assert whether downstream verification accepts an output that should have been rejected.
