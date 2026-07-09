# Q3408: Reuse child-channel state

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `confidential_key_derivation::ckd(...)` and exploit `from_be_bytes_mod_order` so concurrently running sessions reuse a child-channel or waitpoint namespace for `order`, letting attacker messages cross sessions and leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/confidential_key_derivation/scalar_wrapper.rs::from_be_bytes_mod_order`
- Entrypoint: `confidential_key_derivation::ckd(...)`
- Attacker controls: `bytes`, `protocol message timing`
- Exploit idea: Run concurrent sessions with overlapping peers and cross-wire `order` messages between child-channel namespaces.
- Invariant to test: Concurrent sessions must not share child-channel or waitpoint identity for `order`.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `confidential_key_derivation::ckd(...)`, let one malicious participant inject conflicting, replayed, or cross-context `order` data into `from_be_bytes_mod_order`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
