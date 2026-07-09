# Q1641: Equivocate per recipient

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `ecdsa::robust_ecdsa::sign::sign(...)` and send recipient-specific `degree-2t share` variants into `sign` so different honest parties bind different views of `degree-2t share` yet still converge on an accepted downstream output, leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/ecdsa/robust_ecdsa/sign.rs::sign`
- Entrypoint: `ecdsa::robust_ecdsa::sign::sign(...)`
- Attacker controls: `participants`, `coordinator`, `max_malicious`, `public_key`, `protocol message timing`
- Exploit idea: Feed different `degree-2t share` values to different honest parties and test whether `degree-2t share` still converges without detection.
- Invariant to test: All honest parties must observe one consistent `degree-2t share` / `degree-2t share` transcript for the same round.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `ecdsa::robust_ecdsa::sign::sign(...)`, let one malicious participant inject conflicting, replayed, or cross-context `degree-2t share` data into `sign`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
