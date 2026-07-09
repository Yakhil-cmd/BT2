# Q939: Desync batched indices

## Question
Can a malicious network peer or malicious coordinator below threshold enter through `Protocol::message(...)` during `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and use crafted batching inputs in `header`, `protocol message timing` so `recv` remaps one party's `child channel` to another party's `message buffer` through index, row, or column confusion, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/protocol/internal.rs::recv`
- Entrypoint: `Protocol::message(...)` during `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `header`, `protocol message timing`
- Exploit idea: Exploit array, row, column, or index confusion to remap one participant's `child channel` to another.
- Invariant to test: Batched helpers must preserve the original participant-to-`child channel` mapping.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `Protocol::message(...)` during `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`, let one malicious participant inject conflicting, replayed, or cross-context `child channel` data into `recv`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
