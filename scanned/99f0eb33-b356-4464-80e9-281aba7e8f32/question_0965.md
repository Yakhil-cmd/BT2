# Q965: Desync batched indices

## Question
Can a malicious network peer or malicious coordinator below threshold enter through `Protocol::message(...)` during `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and use crafted batching inputs in `header`, `data`, `protocol message timing` so `send_many` remaps one party's `send` to another party's `send` through index, row, or column confusion, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/protocol/internal.rs::send_many`
- Entrypoint: `Protocol::message(...)` during `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `header`, `data`, `protocol message timing`
- Exploit idea: Exploit array, row, column, or index confusion to remap one participant's `send` to another.
- Invariant to test: Batched helpers must preserve the original participant-to-`send` mapping.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `Protocol::message(...)` during `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`, let one malicious participant inject conflicting, replayed, or cross-context `send` data into `send_many`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
