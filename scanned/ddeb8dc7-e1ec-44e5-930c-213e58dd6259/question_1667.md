# Q1667: Equivocate per recipient

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)` and send recipient-specific `key package` variants into `construct_key_package` so different honest parties bind different views of `presignature context` yet still converge on an accepted downstream output, leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/frost/eddsa/sign.rs::construct_key_package`
- Entrypoint: `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)`
- Attacker controls: `threshold`, `signing_share`, `verifying_key`, `protocol message timing`
- Exploit idea: Feed different `key package` values to different honest parties and test whether `presignature context` still converges without detection.
- Invariant to test: All honest parties must observe one consistent `key package` / `presignature context` transcript for the same round.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)`, let one malicious participant inject conflicting, replayed, or cross-context `key package` data into `construct_key_package`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
