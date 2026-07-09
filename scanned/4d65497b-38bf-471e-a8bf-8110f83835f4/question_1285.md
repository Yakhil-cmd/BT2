# Q1285: Equivocate per recipient

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `ecdsa::ot_based_ecdsa::presign(...)`, `ecdsa::ot_based_ecdsa::sign(...)`, or the triple-generation pipeline` and send recipient-specific `sigma share` variants into `correlated_ot_sender` so different honest parties bind different views of `beta share` yet still converge on an accepted downstream output, leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/ecdsa/ot_based_ecdsa/triples/correlated_ot_extension.rs::correlated_ot_sender`
- Entrypoint: `ecdsa::ot_based_ecdsa::presign(...)`, `ecdsa::ot_based_ecdsa::sign(...)`, or the triple-generation pipeline`
- Attacker controls: `params`, `delta`, `k`, `protocol message timing`
- Exploit idea: Feed different `sigma share` values to different honest parties and test whether `beta share` still converges without detection.
- Invariant to test: All honest parties must observe one consistent `sigma share` / `beta share` transcript for the same round.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `ecdsa::ot_based_ecdsa::presign(...)`, `ecdsa::ot_based_ecdsa::sign(...)`, or the triple-generation pipeline`, let one malicious participant inject conflicting, replayed, or cross-context `sigma share` data into `correlated_ot_sender`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
