# Q3406: Cross subprotocol messages

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `confidential_key_derivation::ckd(...)` and inject `order` from one subprotocol/channel into another so `from_be_bytes_mod_order` confuses private vs shared or child vs parent context, leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/confidential_key_derivation/scalar_wrapper.rs::from_be_bytes_mod_order`
- Entrypoint: `confidential_key_derivation::ckd(...)`
- Attacker controls: `bytes`, `protocol message timing`
- Exploit idea: Inject child-channel or cross-channel `order` messages where only same-channel traffic should count.
- Invariant to test: Private, shared, parent, and child channel namespaces must not overlap for `order` messages.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `confidential_key_derivation::ckd(...)`, let one malicious participant inject conflicting, replayed, or cross-context `order` data into `from_be_bytes_mod_order`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
