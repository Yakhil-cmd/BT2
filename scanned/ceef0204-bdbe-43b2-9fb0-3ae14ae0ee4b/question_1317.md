# Q1317: Cross subprotocol messages

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `ecdsa::ot_based_ecdsa::triples::generation::generate_triple(...)` and inject `presignature` from one subprotocol/channel into another so `generate_triple` confuses private vs shared or child vs parent context, leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/ecdsa/ot_based_ecdsa/triples/generation.rs::generate_triple`
- Entrypoint: `ecdsa::ot_based_ecdsa::triples::generation::generate_triple(...)`
- Attacker controls: `participants`, `threshold`, `protocol message timing`
- Exploit idea: Inject child-channel or cross-channel `presignature` messages where only same-channel traffic should count.
- Invariant to test: Private, shared, parent, and child channel namespaces must not overlap for `presignature` messages.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `ecdsa::ot_based_ecdsa::triples::generation::generate_triple(...)`, let one malicious participant inject conflicting, replayed, or cross-context `presignature` data into `generate_triple`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
