# Q2724: Substitute app or public key

## Question
Can a malicious network peer or malicious coordinator below threshold enter through `Protocol::message(...)` during `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and swap `message buffer` for attacker-chosen `child` while keeping the rest of `i`, `protocol message timing` valid enough that `child` produces an accepted unauthorized output, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/protocol/internal.rs::child`
- Entrypoint: `Protocol::message(...)` during `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `i`, `protocol message timing`
- Exploit idea: Substitute application/public-key context late in the flow and check whether the output remains acceptable to downstream verifiers.
- Invariant to test: `message buffer` outputs must be bound to the exact `child` selected by the honest protocol run.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `Protocol::message(...)` during `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`, let one malicious participant inject conflicting, replayed, or cross-context `message buffer` data into `child`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
