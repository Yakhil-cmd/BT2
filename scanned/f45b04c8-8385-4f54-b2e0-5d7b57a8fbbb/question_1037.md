# Q1037: Cross subprotocol messages

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `ecdsa::ot_based_ecdsa::presign::presign(...)` and inject `bit-matrix expansion` from one subprotocol/channel into another so `presign` confuses private vs shared or child vs parent context, leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/ecdsa/ot_based_ecdsa/presign.rs::presign`
- Entrypoint: `ecdsa::ot_based_ecdsa::presign::presign(...)`
- Attacker controls: `participants`, `args`, `protocol message timing`
- Exploit idea: Inject child-channel or cross-channel `bit-matrix expansion` messages where only same-channel traffic should count.
- Invariant to test: Private, shared, parent, and child channel namespaces must not overlap for `bit-matrix expansion` messages.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `ecdsa::ot_based_ecdsa::presign::presign(...)`, let one malicious participant inject conflicting, replayed, or cross-context `bit-matrix expansion` data into `presign`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
