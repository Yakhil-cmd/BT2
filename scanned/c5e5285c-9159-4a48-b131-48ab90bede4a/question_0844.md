# Q844: Alias two identities into one slot

## Question
Can a malicious network peer or malicious coordinator below threshold enter through `Protocol::message(...)` during `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and craft `participants`, `waitpoint`, `protocol message timing` so `recv_from_others` treats two logical participants or sessions as the same `message header` slot, overwrites state, and leads to Bypass of threshold signature requirements?

## Target
- File/function: `src/protocol/helpers.rs::recv_from_others`
- Entrypoint: `Protocol::message(...)` during `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `participants`, `waitpoint`, `protocol message timing`
- Exploit idea: Create two attacker-controlled representations that collide onto one `message header` slot inside maps or buffers.
- Invariant to test: No attacker-controlled alias may overwrite another participant's state slot or session slot.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `Protocol::message(...)` during `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`, let one malicious participant inject conflicting, replayed, or cross-context `message header` data into `recv_from_others`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
