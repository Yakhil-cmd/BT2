# Q3089: Equivocate per recipient

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `ecdsa::robust_ecdsa::presign(...)` or `ecdsa::robust_ecdsa::sign(...)` and send recipient-specific `degree-2t share` variants into `zero_secret_polynomial` so different honest parties bind different views of `presign package` yet still converge on an accepted downstream output, leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/ecdsa/robust_ecdsa/presign.rs::zero_secret_polynomial`
- Entrypoint: `ecdsa::robust_ecdsa::presign(...)` or `ecdsa::robust_ecdsa::sign(...)`
- Attacker controls: `degree`, `protocol message timing`
- Exploit idea: Feed different `degree-2t share` values to different honest parties and test whether `presign package` still converges without detection.
- Invariant to test: All honest parties must observe one consistent `degree-2t share` / `presign package` transcript for the same round.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `ecdsa::robust_ecdsa::presign(...)` or `ecdsa::robust_ecdsa::sign(...)`, let one malicious participant inject conflicting, replayed, or cross-context `degree-2t share` data into `zero_secret_polynomial`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
