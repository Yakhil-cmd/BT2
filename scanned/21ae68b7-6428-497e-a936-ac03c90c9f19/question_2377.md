# Q2377: Desync batched indices

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and use crafted batching inputs in `public_key`, `msg_hash` so `verify` remaps one party's `polynomial` to another party's `serialized scalar` through index, row, or column confusion, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/ecdsa/mod.rs::verify`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `public_key`, `msg_hash`
- Exploit idea: Exploit array, row, column, or index confusion to remap one participant's `polynomial` to another.
- Invariant to test: Batched helpers must preserve the original participant-to-`polynomial` mapping.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `ecdsa::verify` that feeds crafted `polynomial` / `serialized scalar` inputs, then assert whether downstream verification accepts an output that should have been rejected.
