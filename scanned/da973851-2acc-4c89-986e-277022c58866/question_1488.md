# Q1488: Equivocate per recipient

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `ecdsa::ot_based_ecdsa::presign(...)`, `ecdsa::ot_based_ecdsa::sign(...)`, or the triple-generation pipeline` and send recipient-specific `OT transcript` variants into `multiplication_sender` so different honest parties bind different views of `Beaver triple` yet still converge on an accepted downstream output, leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/ecdsa/ot_based_ecdsa/triples/multiplication.rs::multiplication_sender`
- Entrypoint: `ecdsa::ot_based_ecdsa::presign(...)`, `ecdsa::ot_based_ecdsa::sign(...)`, or the triple-generation pipeline`
- Attacker controls: `sid`, `a_i`, `b_i`, `precomputed_values`, `protocol message timing`
- Exploit idea: Feed different `OT transcript` values to different honest parties and test whether `Beaver triple` still converges without detection.
- Invariant to test: All honest parties must observe one consistent `OT transcript` / `Beaver triple` transcript for the same round.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `ecdsa::ot_based_ecdsa::presign(...)`, `ecdsa::ot_based_ecdsa::sign(...)`, or the triple-generation pipeline`, let one malicious participant inject conflicting, replayed, or cross-context `OT transcript` data into `multiplication_sender`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
