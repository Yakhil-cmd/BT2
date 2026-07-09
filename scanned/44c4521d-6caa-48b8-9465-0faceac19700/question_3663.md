# Q3663: Desync batched indices

## Question
Can a malicious network peer or malicious coordinator below threshold enter through `Protocol::message(...)` during `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and use crafted batching inputs in `waitpoint`, `message header`, `protocol message timing` so `shared_channel` remaps one party's `shared` to another party's `waitpoint` through index, row, or column confusion, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/protocol/internal.rs::shared_channel`
- Entrypoint: `Protocol::message(...)` during `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `waitpoint`, `message header`, `protocol message timing`
- Exploit idea: Exploit array, row, column, or index confusion to remap one participant's `shared` to another.
- Invariant to test: Batched helpers must preserve the original participant-to-`shared` mapping.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `Protocol::message(...)` during `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`, let one malicious participant inject conflicting, replayed, or cross-context `shared` data into `shared_channel`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
