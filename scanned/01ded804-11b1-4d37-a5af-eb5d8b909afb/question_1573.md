# Q1573: Reuse child-channel state

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `ecdsa::robust_ecdsa::presign::presign(...)` and exploit `presign` so concurrently running sessions reuse a child-channel or waitpoint namespace for `participant set binding`, letting attacker messages cross sessions and leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/ecdsa/robust_ecdsa/presign.rs::presign`
- Entrypoint: `ecdsa::robust_ecdsa::presign::presign(...)`
- Attacker controls: `participants`, `args`, `protocol message timing`
- Exploit idea: Run concurrent sessions with overlapping peers and cross-wire `participant set binding` messages between child-channel namespaces.
- Invariant to test: Concurrent sessions must not share child-channel or waitpoint identity for `participant set binding`.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `ecdsa::robust_ecdsa::presign::presign(...)`, let one malicious participant inject conflicting, replayed, or cross-context `participant set binding` data into `presign`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
