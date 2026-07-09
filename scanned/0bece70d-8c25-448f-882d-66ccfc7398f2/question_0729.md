# Q729: Reuse child-channel state

## Question
Can a single malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, or `refresh(...)` and exploit `public_key_from_commitments` so concurrently running sessions reuse a child-channel or waitpoint namespace for `commitment hash`, letting attacker messages cross sessions and leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/dkg.rs::public_key_from_commitments`
- Entrypoint: `keygen(...)`, `reshare(...)`, or `refresh(...)`
- Attacker controls: `commitments`, `protocol message timing`
- Exploit idea: Run concurrent sessions with overlapping peers and cross-wire `commitment hash` messages between child-channel namespaces.
- Invariant to test: Concurrent sessions must not share child-channel or waitpoint identity for `commitment hash`.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `keygen(...)`, `reshare(...)`, or `refresh(...)`, let one malicious participant inject conflicting, replayed, or cross-context `commitment hash` data into `public_key_from_commitments`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
