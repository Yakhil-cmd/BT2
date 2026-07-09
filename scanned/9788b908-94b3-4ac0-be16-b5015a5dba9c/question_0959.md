# Q959: Substitute app or public key

## Question
Can a malicious network peer or malicious coordinator below threshold enter through `Protocol::message(...)` during `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and swap `waitpoint` for attacker-chosen `message buffer` while keeping the rest of `header`, `data`, `protocol message timing` valid enough that `send_many` produces an accepted unauthorized output, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/protocol/internal.rs::send_many`
- Entrypoint: `Protocol::message(...)` during `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `header`, `data`, `protocol message timing`
- Exploit idea: Substitute application/public-key context late in the flow and check whether the output remains acceptable to downstream verifiers.
- Invariant to test: `waitpoint` outputs must be bound to the exact `message buffer` selected by the honest protocol run.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `Protocol::message(...)` during `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`, let one malicious participant inject conflicting, replayed, or cross-context `waitpoint` data into `send_many`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
