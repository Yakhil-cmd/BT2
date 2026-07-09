# Q3790: Desync batched indices

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and use crafted batching inputs in `rhs` so `add` remaps one party's `hash output` to another party's `polynomial` through index, row, or column confusion, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/crypto/polynomials.rs::add`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `rhs`
- Exploit idea: Exploit array, row, column, or index confusion to remap one participant's `hash output` to another.
- Invariant to test: Batched helpers must preserve the original participant-to-`hash output` mapping.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `crypto::polynomials::add` that feeds crafted `hash output` / `polynomial` inputs, then assert whether downstream verification accepts an output that should have been rejected.
