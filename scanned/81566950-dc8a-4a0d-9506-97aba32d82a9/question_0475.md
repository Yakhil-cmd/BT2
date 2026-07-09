# Q475: Reuse child-channel state

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)` and exploit `do_sign_participant_v1` so concurrently running sessions reuse a child-channel or waitpoint namespace for `v1`, letting attacker messages cross sessions and leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/frost/eddsa/sign.rs::do_sign_participant_v1`
- Entrypoint: `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)`
- Attacker controls: `coordinator`, `threshold`, `keygen_output`, `message`, `protocol message timing`
- Exploit idea: Run concurrent sessions with overlapping peers and cross-wire `v1` messages between child-channel namespaces.
- Invariant to test: Concurrent sessions must not share child-channel or waitpoint identity for `v1`.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)`, let one malicious participant inject conflicting, replayed, or cross-context `v1` data into `do_sign_participant_v1`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
