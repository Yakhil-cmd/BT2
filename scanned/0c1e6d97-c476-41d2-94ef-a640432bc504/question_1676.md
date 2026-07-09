# Q1676: Reuse child-channel state

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)` and exploit `construct_key_package` so concurrently running sessions reuse a child-channel or waitpoint namespace for `signing nonces`, letting attacker messages cross sessions and leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/frost/eddsa/sign.rs::construct_key_package`
- Entrypoint: `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)`
- Attacker controls: `threshold`, `signing_share`, `verifying_key`, `protocol message timing`
- Exploit idea: Run concurrent sessions with overlapping peers and cross-wire `signing nonces` messages between child-channel namespaces.
- Invariant to test: Concurrent sessions must not share child-channel or waitpoint identity for `signing nonces`.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `frost::presign(...)`, `sign_v1(...)`, `sign_v2(...)`, or `redjubjub::sign(...)`, let one malicious participant inject conflicting, replayed, or cross-context `signing nonces` data into `construct_key_package`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
