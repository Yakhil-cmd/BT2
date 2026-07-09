# Q2501: Desync batched indices

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and use crafted batching inputs in `seed` so `build_rng` remaps one party's `witness` to another party's `witness` through index, row, or column confusion, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/crypto/proofs/strobe_transcript.rs::build_rng`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `seed`
- Exploit idea: Exploit array, row, column, or index confusion to remap one participant's `witness` to another.
- Invariant to test: Batched helpers must preserve the original participant-to-`witness` mapping.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `crypto::proofs::strobe_transcript::build_rng` that feeds crafted `witness` / `witness` inputs, then assert whether downstream verification accepts an output that should have been rejected.
