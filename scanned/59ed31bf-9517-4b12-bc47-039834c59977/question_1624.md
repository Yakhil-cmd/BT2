# Q1624: Reuse child-channel state

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `ecdsa::robust_ecdsa::presign(...)` or `ecdsa::robust_ecdsa::sign(...)` and exploit `fut_wrapper` so concurrently running sessions reuse a child-channel or waitpoint namespace for `participant set binding`, letting attacker messages cross sessions and leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/ecdsa/robust_ecdsa/sign.rs::fut_wrapper`
- Entrypoint: `ecdsa::robust_ecdsa::presign(...)` or `ecdsa::robust_ecdsa::sign(...)`
- Attacker controls: `participants`, `coordinator`, `public_key`, `presignature`, `protocol message timing`
- Exploit idea: Run concurrent sessions with overlapping peers and cross-wire `participant set binding` messages between child-channel namespaces.
- Invariant to test: Concurrent sessions must not share child-channel or waitpoint identity for `participant set binding`.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `ecdsa::robust_ecdsa::presign(...)` or `ecdsa::robust_ecdsa::sign(...)`, let one malicious participant inject conflicting, replayed, or cross-context `participant set binding` data into `fut_wrapper`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
