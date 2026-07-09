# Q2301: Desync batched indices

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and use crafted batching inputs in `identifiers`, `shares`, `point` so `eval_exponent_interpolation` remaps one party's `interpolation set` to another party's `exponent` through index, row, or column confusion, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/crypto/polynomials.rs::eval_exponent_interpolation`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `identifiers`, `shares`, `point`
- Exploit idea: Exploit array, row, column, or index confusion to remap one participant's `interpolation set` to another.
- Invariant to test: Batched helpers must preserve the original participant-to-`interpolation set` mapping.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `crypto::polynomials::eval_exponent_interpolation` that feeds crafted `interpolation set` / `exponent` inputs, then assert whether downstream verification accepts an output that should have been rejected.
