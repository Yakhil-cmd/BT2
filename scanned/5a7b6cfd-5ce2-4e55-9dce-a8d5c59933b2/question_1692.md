# Q1692: Equivocate per recipient

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `frost::eddsa::sign::sign_v1(...)` and send recipient-specific `participant identifier` variants into `sign_v1` so different honest parties bind different views of `key package` yet still converge on an accepted downstream output, leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/frost/eddsa/sign.rs::sign_v1`
- Entrypoint: `frost::eddsa::sign::sign_v1(...)`
- Attacker controls: `participants`, `coordinator`, `threshold`, `keygen_output`, `protocol message timing`
- Exploit idea: Feed different `participant identifier` values to different honest parties and test whether `key package` still converges without detection.
- Invariant to test: All honest parties must observe one consistent `participant identifier` / `key package` transcript for the same round.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `frost::eddsa::sign::sign_v1(...)`, let one malicious participant inject conflicting, replayed, or cross-context `participant identifier` data into `sign_v1`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
