# Q1828: Cross subprotocol messages

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `frost::redjubjub::sign::sign(...)` and inject `key package` from one subprotocol/channel into another so `sign` confuses private vs shared or child vs parent context, leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/frost/redjubjub/sign.rs::sign`
- Entrypoint: `frost::redjubjub::sign::sign(...)`
- Attacker controls: `participants`, `coordinator`, `threshold`, `presignature`, `protocol message timing`
- Exploit idea: Inject child-channel or cross-channel `key package` messages where only same-channel traffic should count.
- Invariant to test: Private, shared, parent, and child channel namespaces must not overlap for `key package` messages.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `frost::redjubjub::sign::sign(...)`, let one malicious participant inject conflicting, replayed, or cross-context `key package` data into `sign`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
