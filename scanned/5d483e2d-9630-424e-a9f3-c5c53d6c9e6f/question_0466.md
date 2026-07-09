# Q466: Equivocate per recipient

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)` and send recipient-specific `key package` variants into `do_sign_participant_v1` so different honest parties bind different views of `coordinator-selected signer set` yet still converge on an accepted downstream output, leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/frost/eddsa/sign.rs::do_sign_participant_v1`
- Entrypoint: `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)`
- Attacker controls: `coordinator`, `threshold`, `keygen_output`, `message`, `protocol message timing`
- Exploit idea: Feed different `key package` values to different honest parties and test whether `coordinator-selected signer set` still converges without detection.
- Invariant to test: All honest parties must observe one consistent `key package` / `coordinator-selected signer set` transcript for the same round.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)`, let one malicious participant inject conflicting, replayed, or cross-context `key package` data into `do_sign_participant_v1`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
