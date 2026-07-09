# Q3588: Desync batched indices

## Question
Can a malicious network peer or malicious coordinator below threshold enter through `Protocol::message(...)` during `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and use crafted batching inputs in `from`, `to`, `protocol message timing` so `private_channel` remaps one party's `private_channel` to another party's `private_channel` through index, row, or column confusion, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/protocol/internal.rs::private_channel`
- Entrypoint: `Protocol::message(...)` during `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `from`, `to`, `protocol message timing`
- Exploit idea: Exploit array, row, column, or index confusion to remap one participant's `private_channel` to another.
- Invariant to test: Batched helpers must preserve the original participant-to-`private_channel` mapping.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `Protocol::message(...)` during `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`, let one malicious participant inject conflicting, replayed, or cross-context `private_channel` data into `private_channel`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
