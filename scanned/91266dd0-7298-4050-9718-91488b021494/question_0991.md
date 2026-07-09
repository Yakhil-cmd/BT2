# Q991: Desync batched indices

## Question
Can a malicious network peer or malicious coordinator below threshold enter through `Protocol::message(...)` during `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and use crafted batching inputs in `header`, `to`, `data`, `protocol message timing` so `send_private` remaps one party's `message buffer` to another party's `message header` through index, row, or column confusion, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/protocol/internal.rs::send_private`
- Entrypoint: `Protocol::message(...)` during `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `header`, `to`, `data`, `protocol message timing`
- Exploit idea: Exploit array, row, column, or index confusion to remap one participant's `message buffer` to another.
- Invariant to test: Batched helpers must preserve the original participant-to-`message buffer` mapping.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `Protocol::message(...)` during `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`, let one malicious participant inject conflicting, replayed, or cross-context `message buffer` data into `send_private`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
