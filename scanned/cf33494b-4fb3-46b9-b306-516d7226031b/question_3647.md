# Q3647: Equivocate per recipient

## Question
Can a malicious network peer or malicious coordinator below threshold enter through `Protocol::message(...)` during `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and send recipient-specific `shared channel` variants into `shared_channel` so different honest parties bind different views of `channel tag` yet still converge on an accepted downstream output, leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/protocol/internal.rs::shared_channel`
- Entrypoint: `Protocol::message(...)` during `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `waitpoint`, `message header`, `protocol message timing`
- Exploit idea: Feed different `shared channel` values to different honest parties and test whether `channel tag` still converges without detection.
- Invariant to test: All honest parties must observe one consistent `shared channel` / `channel tag` transcript for the same round.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `Protocol::message(...)` during `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`, let one malicious participant inject conflicting, replayed, or cross-context `shared channel` data into `shared_channel`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
