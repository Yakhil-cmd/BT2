# Q1344: Reorder rounds

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `ecdsa::ot_based_ecdsa::triples::generation::generate_triple_many(...)` and reorder attacker-controlled `OT transcript` messages so `generate_triple_many` satisfies an earlier-round check with later-round data, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/ecdsa/ot_based_ecdsa/triples/generation.rs::generate_triple_many`
- Entrypoint: `ecdsa::ot_based_ecdsa::triples::generation::generate_triple_many(...)`
- Attacker controls: `participants`, `threshold`, `protocol message timing`
- Exploit idea: Deliver later-round `OT transcript` inputs before earlier-round receives complete and watch for premature acceptance.
- Invariant to test: Later-round `OT transcript` data must never satisfy earlier-round `sigma share` checks.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `ecdsa::ot_based_ecdsa::triples::generation::generate_triple_many(...)`, let one malicious participant inject conflicting, replayed, or cross-context `OT transcript` data into `generate_triple_many`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
