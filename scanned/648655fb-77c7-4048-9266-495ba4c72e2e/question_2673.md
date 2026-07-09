# Q2673: Substitute app or public key

## Question
Can a single malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, or `refresh(...)` and swap `new participant set` for attacker-chosen `domain_separator` while keeping the rest of `participant`, `session_id`, `domain_separator`, `commitment`, `protocol message timing` valid enough that `internal_verify_proof_of_knowledge` produces an accepted unauthorized output, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/dkg.rs::internal_verify_proof_of_knowledge`
- Entrypoint: `keygen(...)`, `reshare(...)`, or `refresh(...)`
- Attacker controls: `participant`, `session_id`, `domain_separator`, `commitment`, `protocol message timing`
- Exploit idea: Substitute application/public-key context late in the flow and check whether the output remains acceptable to downstream verifiers.
- Invariant to test: `new participant set` outputs must be bound to the exact `domain_separator` selected by the honest protocol run.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `keygen(...)`, `reshare(...)`, or `refresh(...)`, let one malicious participant inject conflicting, replayed, or cross-context `new participant set` data into `internal_verify_proof_of_knowledge`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
