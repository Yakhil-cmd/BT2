# Q1116: Reuse child-channel state

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `ecdsa::ot_based_ecdsa::sign::sign(...)` and exploit `sign` so concurrently running sessions reuse a child-channel or waitpoint namespace for `sigma share`, letting attacker messages cross sessions and leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/ecdsa/ot_based_ecdsa/sign.rs::sign`
- Entrypoint: `ecdsa::ot_based_ecdsa::sign::sign(...)`
- Attacker controls: `participants`, `coordinator`, `threshold`, `public_key`, `protocol message timing`
- Exploit idea: Run concurrent sessions with overlapping peers and cross-wire `sigma share` messages between child-channel namespaces.
- Invariant to test: Concurrent sessions must not share child-channel or waitpoint identity for `sigma share`.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `ecdsa::ot_based_ecdsa::sign::sign(...)`, let one malicious participant inject conflicting, replayed, or cross-context `sigma share` data into `sign`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
