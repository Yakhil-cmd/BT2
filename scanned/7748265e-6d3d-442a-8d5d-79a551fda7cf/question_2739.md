# Q2739: Equivocate per recipient

## Question
Can a malicious network peer or malicious coordinator below threshold enter through `Protocol::message(...)` during `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and send recipient-specific `private channel` variants into `encode_with_tag` so different honest parties bind different views of `waitpoint` yet still converge on an accepted downstream output, leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/protocol/internal.rs::encode_with_tag`
- Entrypoint: `Protocol::message(...)` during `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `tag`, `val`, `protocol message timing`
- Exploit idea: Feed different `private channel` values to different honest parties and test whether `waitpoint` still converges without detection.
- Invariant to test: All honest parties must observe one consistent `private channel` / `waitpoint` transcript for the same round.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `Protocol::message(...)` during `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`, let one malicious participant inject conflicting, replayed, or cross-context `private channel` data into `encode_with_tag`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
