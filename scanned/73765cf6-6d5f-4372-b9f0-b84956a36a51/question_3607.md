# Q3607: Substitute app or public key

## Question
Can a malicious network peer or malicious coordinator below threshold enter through `Protocol::message(...)` during `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and swap `message header` for attacker-chosen `shared channel` while keeping the rest of `p0`, `p1`, `protocol message timing` valid enough that `root_private` produces an accepted unauthorized output, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/protocol/internal.rs::root_private`
- Entrypoint: `Protocol::message(...)` during `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `p0`, `p1`, `protocol message timing`
- Exploit idea: Substitute application/public-key context late in the flow and check whether the output remains acceptable to downstream verifiers.
- Invariant to test: `message header` outputs must be bound to the exact `shared channel` selected by the honest protocol run.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `Protocol::message(...)` during `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`, let one malicious participant inject conflicting, replayed, or cross-context `message header` data into `root_private`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
