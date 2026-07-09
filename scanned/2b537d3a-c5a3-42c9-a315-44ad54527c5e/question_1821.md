# Q1821: Equivocate per recipient

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `frost::redjubjub::sign::sign(...)` and send recipient-specific `nonce commitment` variants into `sign` so different honest parties bind different views of `commitments_map` yet still converge on an accepted downstream output, leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/frost/redjubjub/sign.rs::sign`
- Entrypoint: `frost::redjubjub::sign::sign(...)`
- Attacker controls: `participants`, `coordinator`, `threshold`, `presignature`, `protocol message timing`
- Exploit idea: Feed different `nonce commitment` values to different honest parties and test whether `commitments_map` still converges without detection.
- Invariant to test: All honest parties must observe one consistent `nonce commitment` / `commitments_map` transcript for the same round.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `frost::redjubjub::sign::sign(...)`, let one malicious participant inject conflicting, replayed, or cross-context `nonce commitment` data into `sign`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
