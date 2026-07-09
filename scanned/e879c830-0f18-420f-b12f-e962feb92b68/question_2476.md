# Q2476: Desync batched indices

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and use crafted batching inputs in `transcript`, `statement`, `proof` so `verify` remaps one party's `generator binding` to another party's `statement encoding` through index, row, or column confusion, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/crypto/proofs/dlogeq.rs::verify`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `transcript`, `statement`, `proof`
- Exploit idea: Exploit array, row, column, or index confusion to remap one participant's `generator binding` to another.
- Invariant to test: Batched helpers must preserve the original participant-to-`generator binding` mapping.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `crypto::proofs::dlogeq::verify` that feeds crafted `generator binding` / `statement encoding` inputs, then assert whether downstream verification accepts an output that should have been rejected.
