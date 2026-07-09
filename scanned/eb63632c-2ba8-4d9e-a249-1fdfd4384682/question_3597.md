# Q3597: Equivocate per recipient

## Question
Can a malicious network peer or malicious coordinator below threshold enter through `Protocol::message(...)` during `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and send recipient-specific `root_private` variants into `root_private` so different honest parties bind different views of `round message` yet still converge on an accepted downstream output, leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/protocol/internal.rs::root_private`
- Entrypoint: `Protocol::message(...)` during `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `p0`, `p1`, `protocol message timing`
- Exploit idea: Feed different `root_private` values to different honest parties and test whether `round message` still converges without detection.
- Invariant to test: All honest parties must observe one consistent `root_private` / `round message` transcript for the same round.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `Protocol::message(...)` during `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`, let one malicious participant inject conflicting, replayed, or cross-context `root_private` data into `root_private`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
