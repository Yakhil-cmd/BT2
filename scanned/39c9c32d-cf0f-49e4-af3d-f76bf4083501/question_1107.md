# Q1107: Equivocate per recipient

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `ecdsa::ot_based_ecdsa::sign::sign(...)` and send recipient-specific `bit-matrix expansion` variants into `sign` so different honest parties bind different views of `sign` yet still converge on an accepted downstream output, leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/ecdsa/ot_based_ecdsa/sign.rs::sign`
- Entrypoint: `ecdsa::ot_based_ecdsa::sign::sign(...)`
- Attacker controls: `participants`, `coordinator`, `threshold`, `public_key`, `protocol message timing`
- Exploit idea: Feed different `bit-matrix expansion` values to different honest parties and test whether `sign` still converges without detection.
- Invariant to test: All honest parties must observe one consistent `bit-matrix expansion` / `sign` transcript for the same round.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `ecdsa::ot_based_ecdsa::sign::sign(...)`, let one malicious participant inject conflicting, replayed, or cross-context `bit-matrix expansion` data into `sign`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
