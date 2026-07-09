# Q1351: Replay across signing requests

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `ecdsa::ot_based_ecdsa::triples::generation::generate_triple_many(...)` and replay a valid `presignature` generated for one signing request, app context, or chain action into another request so the system authorizes a second action, leading to Cross-chain replay attacks enabling double-spending?

## Target
- File/function: `src/ecdsa/ot_based_ecdsa/triples/generation.rs::generate_triple_many`
- Entrypoint: `ecdsa::ot_based_ecdsa::triples::generation::generate_triple_many(...)`
- Attacker controls: `participants`, `threshold`, `protocol message timing`
- Exploit idea: Replay a valid output from one request or chain context into another and check whether downstream authorization treats it as fresh.
- Invariant to test: A valid `presignature` for one request must be unusable for any second request or chain action.
- Expected Immunefi impact: Cross-chain replay attacks enabling double-spending
- Fast validation: Run two or more local protocol instances around `ecdsa::ot_based_ecdsa::triples::generation::generate_triple_many(...)`, let one malicious participant inject conflicting, replayed, or cross-context `presignature` data into `generate_triple_many`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
