# Q1770: Equivocate per recipient

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)` and send recipient-specific `signing nonces` variants into `construct_key_package` so different honest parties bind different views of `construct` yet still converge on an accepted downstream output, leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/frost/redjubjub/sign.rs::construct_key_package`
- Entrypoint: `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)`
- Attacker controls: `threshold`, `keygen_output`, `protocol message timing`
- Exploit idea: Feed different `signing nonces` values to different honest parties and test whether `construct` still converges without detection.
- Invariant to test: All honest parties must observe one consistent `signing nonces` / `construct` transcript for the same round.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)`, let one malicious participant inject conflicting, replayed, or cross-context `signing nonces` data into `construct_key_package`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
