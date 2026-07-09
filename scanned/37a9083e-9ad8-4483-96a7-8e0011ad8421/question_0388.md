# Q388: Equivocate per recipient

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `ecdsa::robust_ecdsa::presign(...)` or `ecdsa::robust_ecdsa::sign(...)` and send recipient-specific `participant set binding` variants into `do_sign_participant` so different honest parties bind different views of `presign package` yet still converge on an accepted downstream output, leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/ecdsa/robust_ecdsa/sign.rs::do_sign_participant`
- Entrypoint: `ecdsa::robust_ecdsa::presign(...)` or `ecdsa::robust_ecdsa::sign(...)`
- Attacker controls: `participants`, `coordinator`, `presignature`, `msg_hash`, `protocol message timing`
- Exploit idea: Feed different `participant set binding` values to different honest parties and test whether `presign package` still converges without detection.
- Invariant to test: All honest parties must observe one consistent `participant set binding` / `presign package` transcript for the same round.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `ecdsa::robust_ecdsa::presign(...)` or `ecdsa::robust_ecdsa::sign(...)`, let one malicious participant inject conflicting, replayed, or cross-context `participant set binding` data into `do_sign_participant`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
