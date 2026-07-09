# Q2039: Cross subprotocol messages

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)` and inject `coordinator-selected signer set` from one subprotocol/channel into another so `assert_sign_inputs` confuses private vs shared or child vs parent context, leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/frost/mod.rs::assert_sign_inputs`
- Entrypoint: `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)`
- Attacker controls: `participants`, `coordinator`, `threshold`, `protocol message timing`
- Exploit idea: Inject child-channel or cross-channel `coordinator-selected signer set` messages where only same-channel traffic should count.
- Invariant to test: Private, shared, parent, and child channel namespaces must not overlap for `coordinator-selected signer set` messages.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)`, let one malicious participant inject conflicting, replayed, or cross-context `coordinator-selected signer set` data into `assert_sign_inputs`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
