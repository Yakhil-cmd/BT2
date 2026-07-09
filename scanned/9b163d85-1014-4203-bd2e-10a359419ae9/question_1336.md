# Q1336: Equivocate per recipient

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `ecdsa::ot_based_ecdsa::triples::generation::generate_triple_many(...)` and send recipient-specific `alpha share` variants into `generate_triple_many` so different honest parties bind different views of `triple share` yet still converge on an accepted downstream output, leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/ecdsa/ot_based_ecdsa/triples/generation.rs::generate_triple_many`
- Entrypoint: `ecdsa::ot_based_ecdsa::triples::generation::generate_triple_many(...)`
- Attacker controls: `participants`, `threshold`, `protocol message timing`
- Exploit idea: Feed different `alpha share` values to different honest parties and test whether `triple share` still converges without detection.
- Invariant to test: All honest parties must observe one consistent `alpha share` / `triple share` transcript for the same round.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `ecdsa::ot_based_ecdsa::triples::generation::generate_triple_many(...)`, let one malicious participant inject conflicting, replayed, or cross-context `alpha share` data into `generate_triple_many`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
