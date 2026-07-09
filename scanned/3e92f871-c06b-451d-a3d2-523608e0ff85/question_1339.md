# Q1339: Mismatch commitment and share

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `ecdsa::ot_based_ecdsa::triples::generation::generate_triple_many(...)` and pair a valid-looking `MTA package` with a different `big_r` reveal so `generate_triple_many` checks each piece in isolation but never the combined statement, causing Cryptographic flaws?

## Target
- File/function: `src/ecdsa/ot_based_ecdsa/triples/generation.rs::generate_triple_many`
- Entrypoint: `ecdsa::ot_based_ecdsa::triples::generation::generate_triple_many(...)`
- Attacker controls: `participants`, `threshold`, `protocol message timing`
- Exploit idea: Commit to one `MTA package` and reveal another `big_r` that still satisfies separate local checks.
- Invariant to test: A commitment and its corresponding `MTA package` reveal must be validated as the same statement.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Run two or more local protocol instances around `ecdsa::ot_based_ecdsa::triples::generation::generate_triple_many(...)`, let one malicious participant inject conflicting, replayed, or cross-context `MTA package` data into `generate_triple_many`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
