# Q491: Equivocate per recipient

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)` and send recipient-specific `participant identifier` variants into `do_sign_participant_v2` so different honest parties bind different views of `nonce commitment` yet still converge on an accepted downstream output, leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/frost/eddsa/sign.rs::do_sign_participant_v2`
- Entrypoint: `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)`
- Attacker controls: `coordinator`, `threshold`, `presignature`, `keygen_output`, `protocol message timing`
- Exploit idea: Feed different `participant identifier` values to different honest parties and test whether `nonce commitment` still converges without detection.
- Invariant to test: All honest parties must observe one consistent `participant identifier` / `nonce commitment` transcript for the same round.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)`, let one malicious participant inject conflicting, replayed, or cross-context `participant identifier` data into `do_sign_participant_v2`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
