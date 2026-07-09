# Q1751: Cross subprotocol messages

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `frost::presign(...)` and inject `key package` from one subprotocol/channel into another so `presign` confuses private vs shared or child vs parent context, leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/frost/mod.rs::presign`
- Entrypoint: `frost::presign(...)`
- Attacker controls: `participants`, `args`, `protocol message timing`
- Exploit idea: Inject child-channel or cross-channel `key package` messages where only same-channel traffic should count.
- Invariant to test: Private, shared, parent, and child channel namespaces must not overlap for `key package` messages.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `frost::presign(...)`, let one malicious participant inject conflicting, replayed, or cross-context `key package` data into `presign`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
