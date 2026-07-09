# Q1795: Equivocate per recipient

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)` and send recipient-specific `signing nonces` variants into `fut_wrapper` so different honest parties bind different views of `presignature context` yet still converge on an accepted downstream output, leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/frost/redjubjub/sign.rs::fut_wrapper`
- Entrypoint: `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)`
- Attacker controls: `participants`, `coordinator`, `threshold`, `presignature`, `protocol message timing`
- Exploit idea: Feed different `signing nonces` values to different honest parties and test whether `presignature context` still converges without detection.
- Invariant to test: All honest parties must observe one consistent `signing nonces` / `presignature context` transcript for the same round.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)`, let one malicious participant inject conflicting, replayed, or cross-context `signing nonces` data into `fut_wrapper`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
