# Q2601: Reuse child-channel state

## Question
Can a single malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, or `refresh(...)` and exploit `broadcast_success` so concurrently running sessions reuse a child-channel or waitpoint namespace for `session_id`, letting attacker messages cross sessions and leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/dkg.rs::broadcast_success`
- Entrypoint: `keygen(...)`, `reshare(...)`, or `refresh(...)`
- Attacker controls: `participants`, `session_id`, `protocol message timing`
- Exploit idea: Run concurrent sessions with overlapping peers and cross-wire `session_id` messages between child-channel namespaces.
- Invariant to test: Concurrent sessions must not share child-channel or waitpoint identity for `session_id`.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `keygen(...)`, `reshare(...)`, or `refresh(...)`, let one malicious participant inject conflicting, replayed, or cross-context `session_id` data into `broadcast_success`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
