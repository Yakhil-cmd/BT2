# Q1615: Equivocate per recipient

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `ecdsa::robust_ecdsa::presign(...)` or `ecdsa::robust_ecdsa::sign(...)` and send recipient-specific `wrapper` variants into `fut_wrapper` so different honest parties bind different views of `big_r share` yet still converge on an accepted downstream output, leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/ecdsa/robust_ecdsa/sign.rs::fut_wrapper`
- Entrypoint: `ecdsa::robust_ecdsa::presign(...)` or `ecdsa::robust_ecdsa::sign(...)`
- Attacker controls: `participants`, `coordinator`, `public_key`, `presignature`, `protocol message timing`
- Exploit idea: Feed different `wrapper` values to different honest parties and test whether `big_r share` still converges without detection.
- Invariant to test: All honest parties must observe one consistent `wrapper` / `big_r share` transcript for the same round.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `ecdsa::robust_ecdsa::presign(...)` or `ecdsa::robust_ecdsa::sign(...)`, let one malicious participant inject conflicting, replayed, or cross-context `wrapper` data into `fut_wrapper`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
