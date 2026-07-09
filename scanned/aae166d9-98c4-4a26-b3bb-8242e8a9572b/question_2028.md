# Q2028: Equivocate per recipient

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)` and send recipient-specific `coordinator-selected signer set` variants into `assert_sign_inputs` so different honest parties bind different views of `coordinator-selected signer set` yet still converge on an accepted downstream output, leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/frost/mod.rs::assert_sign_inputs`
- Entrypoint: `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)`
- Attacker controls: `participants`, `coordinator`, `threshold`, `protocol message timing`
- Exploit idea: Feed different `coordinator-selected signer set` values to different honest parties and test whether `coordinator-selected signer set` still converges without detection.
- Invariant to test: All honest parties must observe one consistent `coordinator-selected signer set` / `coordinator-selected signer set` transcript for the same round.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)`, let one malicious participant inject conflicting, replayed, or cross-context `coordinator-selected signer set` data into `assert_sign_inputs`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
