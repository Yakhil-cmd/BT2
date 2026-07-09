# Q628: Reuse child-channel state

## Question
Can a single malicious participant or malicious coordinator below threshold enter through `confidential_key_derivation::ckd(...)` and exploit `do_ckd_coordinator` so concurrently running sessions reuse a child-channel or waitpoint namespace for `derived key output`, letting attacker messages cross sessions and leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/confidential_key_derivation/protocol.rs::do_ckd_coordinator`
- Entrypoint: `confidential_key_derivation::ckd(...)`
- Attacker controls: `participants`, `key_pair`, `app_id`, `app_pk`, `protocol message timing`
- Exploit idea: Run concurrent sessions with overlapping peers and cross-wire `derived key output` messages between child-channel namespaces.
- Invariant to test: Concurrent sessions must not share child-channel or waitpoint identity for `derived key output`.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `confidential_key_derivation::ckd(...)`, let one malicious participant inject conflicting, replayed, or cross-context `derived key output` data into `do_ckd_coordinator`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
