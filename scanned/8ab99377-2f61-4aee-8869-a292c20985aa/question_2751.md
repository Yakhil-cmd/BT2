# Q2751: Reorder rounds

## Question
Can a malicious network peer or malicious coordinator below threshold enter through `Protocol::message(...)` during `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and reorder attacker-controlled `tag` messages so `encode_with_tag` satisfies an earlier-round check with later-round data, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/protocol/internal.rs::encode_with_tag`
- Entrypoint: `Protocol::message(...)` during `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `tag`, `val`, `protocol message timing`
- Exploit idea: Deliver later-round `tag` inputs before earlier-round receives complete and watch for premature acceptance.
- Invariant to test: Later-round `tag` data must never satisfy earlier-round `child channel` checks.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `Protocol::message(...)` during `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`, let one malicious participant inject conflicting, replayed, or cross-context `tag` data into `encode_with_tag`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
