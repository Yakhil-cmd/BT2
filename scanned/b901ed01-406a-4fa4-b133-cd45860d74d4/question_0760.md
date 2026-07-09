# Q760: Reuse helper output under new signer set

## Question
Can a single malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, or `refresh(...)` and carry a previously valid `received share` helper output into a different participant set or threshold context where `validate_received_share` still accepts it, leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/dkg.rs::validate_received_share`
- Entrypoint: `keygen(...)`, `reshare(...)`, or `refresh(...)`
- Attacker controls: `commitment`, `from`, `signing_share_from`, `protocol message timing`
- Exploit idea: Port helper output from one threshold or participant set into another flow that should have rejected it.
- Invariant to test: Helper outputs for `received share` must be invalid outside their original participant and threshold context.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `keygen(...)`, `reshare(...)`, or `refresh(...)`, let one malicious participant inject conflicting, replayed, or cross-context `received share` data into `validate_received_share`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
