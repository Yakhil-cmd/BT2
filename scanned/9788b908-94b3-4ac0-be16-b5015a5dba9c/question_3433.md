# Q3433: Reuse child-channel state

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `confidential_key_derivation::ckd(...)` and exploit `from_okm` so concurrently running sessions reuse a child-channel or waitpoint namespace for `from`, letting attacker messages cross sessions and leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/confidential_key_derivation/scalar_wrapper.rs::from_okm`
- Entrypoint: `confidential_key_derivation::ckd(...)`
- Attacker controls: `okm`, `Self`, `protocol message timing`
- Exploit idea: Run concurrent sessions with overlapping peers and cross-wire `from` messages between child-channel namespaces.
- Invariant to test: Concurrent sessions must not share child-channel or waitpoint identity for `from`.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `confidential_key_derivation::ckd(...)`, let one malicious participant inject conflicting, replayed, or cross-context `from` data into `from_okm`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
