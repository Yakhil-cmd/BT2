# Q1342: Substitute app or public key

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `ecdsa::ot_based_ecdsa::triples::generation::generate_triple_many(...)` and swap `MTA package` for attacker-chosen `Beaver triple` while keeping the rest of `participants`, `threshold`, `protocol message timing` valid enough that `generate_triple_many` produces an accepted unauthorized output, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/ecdsa/ot_based_ecdsa/triples/generation.rs::generate_triple_many`
- Entrypoint: `ecdsa::ot_based_ecdsa::triples::generation::generate_triple_many(...)`
- Attacker controls: `participants`, `threshold`, `protocol message timing`
- Exploit idea: Substitute application/public-key context late in the flow and check whether the output remains acceptable to downstream verifiers.
- Invariant to test: `MTA package` outputs must be bound to the exact `Beaver triple` selected by the honest protocol run.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `ecdsa::ot_based_ecdsa::triples::generation::generate_triple_many(...)`, let one malicious participant inject conflicting, replayed, or cross-context `MTA package` data into `generate_triple_many`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
