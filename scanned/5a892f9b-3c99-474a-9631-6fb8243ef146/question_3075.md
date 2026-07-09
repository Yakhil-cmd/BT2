# Q3075: Cross subprotocol messages

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `ecdsa::robust_ecdsa::presign(...)` or `ecdsa::robust_ecdsa::sign(...)` and inject `max_malicious bound` from one subprotocol/channel into another so `add_shares` confuses private vs shared or child vs parent context, leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/ecdsa/robust_ecdsa/presign.rs::add_shares`
- Entrypoint: `ecdsa::robust_ecdsa::presign(...)` or `ecdsa::robust_ecdsa::sign(...)`
- Attacker controls: `shares`, `protocol message timing`
- Exploit idea: Inject child-channel or cross-channel `max_malicious bound` messages where only same-channel traffic should count.
- Invariant to test: Private, shared, parent, and child channel namespaces must not overlap for `max_malicious bound` messages.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `ecdsa::robust_ecdsa::presign(...)` or `ecdsa::robust_ecdsa::sign(...)`, let one malicious participant inject conflicting, replayed, or cross-context `max_malicious bound` data into `add_shares`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
