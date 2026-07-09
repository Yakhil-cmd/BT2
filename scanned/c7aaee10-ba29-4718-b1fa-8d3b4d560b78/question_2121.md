# Q2121: Desync batched indices

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and use crafted batching inputs in `val`, `r` so `compute` remaps one party's `polynomial commitment` to another party's `domain-separated hash` through index, row, or column confusion, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/crypto/commitment.rs::compute`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `val`, `r`
- Exploit idea: Exploit array, row, column, or index confusion to remap one participant's `polynomial commitment` to another.
- Invariant to test: Batched helpers must preserve the original participant-to-`polynomial commitment` mapping.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `crypto::commitment::compute` that feeds crafted `polynomial commitment` / `domain-separated hash` inputs, then assert whether downstream verification accepts an output that should have been rejected.
