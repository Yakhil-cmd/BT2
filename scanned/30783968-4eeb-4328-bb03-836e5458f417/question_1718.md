# Q1718: Equivocate per recipient

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `frost::eddsa::sign::sign_v2(...)` and send recipient-specific `v2` variants into `sign_v2` so different honest parties bind different views of `v2` yet still converge on an accepted downstream output, leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/frost/eddsa/sign.rs::sign_v2`
- Entrypoint: `frost::eddsa::sign::sign_v2(...)`
- Attacker controls: `participants`, `coordinator`, `threshold`, `presignature`, `protocol message timing`
- Exploit idea: Feed different `v2` values to different honest parties and test whether `v2` still converges without detection.
- Invariant to test: All honest parties must observe one consistent `v2` / `v2` transcript for the same round.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `frost::eddsa::sign::sign_v2(...)`, let one malicious participant inject conflicting, replayed, or cross-context `v2` data into `sign_v2`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
