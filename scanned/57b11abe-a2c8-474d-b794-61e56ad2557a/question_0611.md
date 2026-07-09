# Q611: Iterate toward hidden state

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `confidential_key_derivation::ciphersuite::verify_signature(...)` and make repeated attacker-chosen queries around `verify_signature` so the returned `big_y` or `derived key output` values reveal linear information about hidden shares or nonce material over time, causing Information disclosure of sensitive MPC state?

## Target
- File/function: `src/confidential_key_derivation/ciphersuite.rs::verify_signature`
- Entrypoint: `confidential_key_derivation::ciphersuite::verify_signature(...)`
- Attacker controls: `verifying_key`, `msg`, `signature`, `protocol message timing`
- Exploit idea: Collect many attacker-chosen outputs that depend on `big_y` and test whether linear relations reveal hidden shares or nonce structure over time.
- Invariant to test: Public-facing return values derived from `big_y` must not allow iterative reconstruction of hidden state across repeated queries.
- Expected Immunefi impact: Information disclosure of sensitive MPC state
- Fast validation: Run two or more local protocol instances around `confidential_key_derivation::ciphersuite::verify_signature(...)`, let one malicious participant inject conflicting, replayed, or cross-context `big_y` data into `verify_signature`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
