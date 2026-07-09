# Q3355: Cross subprotocol messages

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `confidential_key_derivation::ckd(...)` and inject `encrypted CKD output` from one subprotocol/channel into another so `hash_to_scalar` confuses private vs shared or child vs parent context, leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/confidential_key_derivation/ciphersuite.rs::hash_to_scalar`
- Entrypoint: `confidential_key_derivation::ckd(...)`
- Attacker controls: `domain`, `msg`, `protocol message timing`
- Exploit idea: Inject child-channel or cross-channel `encrypted CKD output` messages where only same-channel traffic should count.
- Invariant to test: Private, shared, parent, and child channel namespaces must not overlap for `encrypted CKD output` messages.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `confidential_key_derivation::ckd(...)`, let one malicious participant inject conflicting, replayed, or cross-context `encrypted CKD output` data into `hash_to_scalar`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
