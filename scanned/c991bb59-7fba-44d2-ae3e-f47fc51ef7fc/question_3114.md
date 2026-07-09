# Q3114: Equivocate per recipient

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)` and send recipient-specific `commitments_map` variants into `fut_wrapper_v1` so different honest parties bind different views of `participant identifier` yet still converge on an accepted downstream output, leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/frost/eddsa/sign.rs::fut_wrapper_v1`
- Entrypoint: `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)`
- Attacker controls: `participants`, `coordinator`, `threshold`, `keygen_output`, `protocol message timing`
- Exploit idea: Feed different `commitments_map` values to different honest parties and test whether `participant identifier` still converges without detection.
- Invariant to test: All honest parties must observe one consistent `commitments_map` / `participant identifier` transcript for the same round.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)`, let one malicious participant inject conflicting, replayed, or cross-context `commitments_map` data into `fut_wrapper_v1`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
