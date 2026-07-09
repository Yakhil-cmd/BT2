# Q3841: Desync batched indices

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and use crafted batching inputs in `participant` so `eval_at_participant` remaps one party's `polynomial` to another party's `eval` through index, row, or column confusion, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/crypto/polynomials.rs::eval_at_participant`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `participant`
- Exploit idea: Exploit array, row, column, or index confusion to remap one participant's `polynomial` to another.
- Invariant to test: Batched helpers must preserve the original participant-to-`polynomial` mapping.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `crypto::polynomials::eval_at_participant` that feeds crafted `polynomial` / `eval` inputs, then assert whether downstream verification accepts an output that should have been rejected.
