# Q1459: Accept zero or identity input

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `ecdsa::ot_based_ecdsa::presign(...)`, `ecdsa::ot_based_ecdsa::sign(...)`, or the triple-generation pipeline` with attacker-chosen `participants`, `sid`, `av_iv`, `bv_iv`, `protocol message timing` and make `multiplication_many` accept a zero or identity-valued `sigma share` that should be rejected, causing Cryptographic flaws?

## Target
- File/function: `src/ecdsa/ot_based_ecdsa/triples/multiplication.rs::multiplication_many`
- Entrypoint: `ecdsa::ot_based_ecdsa::presign(...)`, `ecdsa::ot_based_ecdsa::sign(...)`, or the triple-generation pipeline`
- Attacker controls: `participants`, `sid`, `av_iv`, `bv_iv`, `protocol message timing`
- Exploit idea: Inject zero, identity, or empty-form `sigma share` values exactly where the helper assumes they cannot appear.
- Invariant to test: Zero or identity-valued `sigma share` inputs must be rejected before any interpolation, proof, or signature step.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Run two or more local protocol instances around `ecdsa::ot_based_ecdsa::presign(...)`, `ecdsa::ot_based_ecdsa::sign(...)`, or the triple-generation pipeline`, let one malicious participant inject conflicting, replayed, or cross-context `sigma share` data into `multiplication_many`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
