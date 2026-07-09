# Q2606: Reuse helper output under new signer set

## Question
Can a single malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, or `refresh(...)` and carry a previously valid `old participant set` helper output into a different participant set or threshold context where `broadcast_success` still accepts it, leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/dkg.rs::broadcast_success`
- Entrypoint: `keygen(...)`, `reshare(...)`, or `refresh(...)`
- Attacker controls: `participants`, `session_id`, `protocol message timing`
- Exploit idea: Port helper output from one threshold or participant set into another flow that should have rejected it.
- Invariant to test: Helper outputs for `old participant set` must be invalid outside their original participant and threshold context.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `keygen(...)`, `reshare(...)`, or `refresh(...)`, let one malicious participant inject conflicting, replayed, or cross-context `old participant set` data into `broadcast_success`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
