# Q1310: Equivocate per recipient

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `ecdsa::ot_based_ecdsa::triples::generation::generate_triple(...)` and send recipient-specific `generate_triple` variants into `generate_triple` so different honest parties bind different views of `Beaver triple` yet still converge on an accepted downstream output, leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/ecdsa/ot_based_ecdsa/triples/generation.rs::generate_triple`
- Entrypoint: `ecdsa::ot_based_ecdsa::triples::generation::generate_triple(...)`
- Attacker controls: `participants`, `threshold`, `protocol message timing`
- Exploit idea: Feed different `generate_triple` values to different honest parties and test whether `Beaver triple` still converges without detection.
- Invariant to test: All honest parties must observe one consistent `generate_triple` / `Beaver triple` transcript for the same round.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `ecdsa::ot_based_ecdsa::triples::generation::generate_triple(...)`, let one malicious participant inject conflicting, replayed, or cross-context `generate_triple` data into `generate_triple`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
