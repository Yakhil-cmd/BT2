# Q1114: Cross subprotocol messages

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `ecdsa::ot_based_ecdsa::sign::sign(...)` and inject `MTA package` from one subprotocol/channel into another so `sign` confuses private vs shared or child vs parent context, leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/ecdsa/ot_based_ecdsa/sign.rs::sign`
- Entrypoint: `ecdsa::ot_based_ecdsa::sign::sign(...)`
- Attacker controls: `participants`, `coordinator`, `threshold`, `public_key`, `protocol message timing`
- Exploit idea: Inject child-channel or cross-channel `MTA package` messages where only same-channel traffic should count.
- Invariant to test: Private, shared, parent, and child channel namespaces must not overlap for `MTA package` messages.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `ecdsa::ot_based_ecdsa::sign::sign(...)`, let one malicious participant inject conflicting, replayed, or cross-context `MTA package` data into `sign`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
