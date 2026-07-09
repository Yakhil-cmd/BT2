# Q549: Cross subprotocol messages

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)` and inject `signing nonces` from one subprotocol/channel into another so `do_sign_coordinator` confuses private vs shared or child vs parent context, leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/frost/redjubjub/sign.rs::do_sign_coordinator`
- Entrypoint: `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)`
- Attacker controls: `participants`, `threshold`, `presignature`, `keygen_output`, `protocol message timing`
- Exploit idea: Inject child-channel or cross-channel `signing nonces` messages where only same-channel traffic should count.
- Invariant to test: Private, shared, parent, and child channel namespaces must not overlap for `signing nonces` messages.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)`, let one malicious participant inject conflicting, replayed, or cross-context `signing nonces` data into `do_sign_coordinator`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
