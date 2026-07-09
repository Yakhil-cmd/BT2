# Q42: Reuse helper output under new signer set

## Question
Can a single malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, or `refresh(...)` and carry a previously valid `keys` helper output into a different participant set or threshold context where `assert_reshare_keys_invariants` still accepts it, leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/dkg.rs::assert_reshare_keys_invariants`
- Entrypoint: `keygen(...)`, `reshare(...)`, or `refresh(...)`
- Attacker controls: `participants`, `threshold`, `old_participants`, `old_threshold`, `protocol message timing`
- Exploit idea: Port helper output from one threshold or participant set into another flow that should have rejected it.
- Invariant to test: Helper outputs for `keys` must be invalid outside their original participant and threshold context.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `keygen(...)`, `reshare(...)`, or `refresh(...)`, let one malicious participant inject conflicting, replayed, or cross-context `keys` data into `assert_reshare_keys_invariants`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
