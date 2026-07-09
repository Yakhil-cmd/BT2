# Q2679: Desync batched indices

## Question
Can a single malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, or `refresh(...)` and use crafted batching inputs in `participant`, `session_id`, `domain_separator`, `commitment`, `protocol message timing` so `internal_verify_proof_of_knowledge` remaps one party's `coefficient commitment` to another party's `received share` through index, row, or column confusion, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/dkg.rs::internal_verify_proof_of_knowledge`
- Entrypoint: `keygen(...)`, `reshare(...)`, or `refresh(...)`
- Attacker controls: `participant`, `session_id`, `domain_separator`, `commitment`, `protocol message timing`
- Exploit idea: Exploit array, row, column, or index confusion to remap one participant's `coefficient commitment` to another.
- Invariant to test: Batched helpers must preserve the original participant-to-`coefficient commitment` mapping.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `keygen(...)`, `reshare(...)`, or `refresh(...)`, let one malicious participant inject conflicting, replayed, or cross-context `coefficient commitment` data into `internal_verify_proof_of_knowledge`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
