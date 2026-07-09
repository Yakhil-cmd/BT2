# Q1315: Omit context from rerandomization

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `ecdsa::ot_based_ecdsa::triples::generation::generate_triple(...)` and exploit `generate_triple` so `presignature` is not fully bound to message, participant set, transcript, or presign context, enabling Bypass of threshold signature requirements?

## Target
- File/function: `src/ecdsa/ot_based_ecdsa/triples/generation.rs::generate_triple`
- Entrypoint: `ecdsa::ot_based_ecdsa::triples::generation::generate_triple(...)`
- Attacker controls: `participants`, `threshold`, `protocol message timing`
- Exploit idea: Change message, signer set, or transcript context while reusing the same `presignature` helper material.
- Invariant to test: Derived or rerandomized `presignature` outputs must be bound to message, signer set, and transcript context.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `ecdsa::ot_based_ecdsa::triples::generation::generate_triple(...)`, let one malicious participant inject conflicting, replayed, or cross-context `presignature` data into `generate_triple`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
