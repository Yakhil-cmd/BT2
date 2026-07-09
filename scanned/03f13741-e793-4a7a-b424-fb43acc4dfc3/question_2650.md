# Q2650: Reorder rounds

## Question
Can a single malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, or `refresh(...)` and reorder attacker-controlled `public key commitments` messages so `insert_identity_if_missing` satisfies an earlier-round check with later-round data, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/dkg.rs::insert_identity_if_missing`
- Entrypoint: `keygen(...)`, `reshare(...)`, or `refresh(...)`
- Attacker controls: `threshold`, `commitment_i`, `protocol message timing`
- Exploit idea: Deliver later-round `public key commitments` inputs before earlier-round receives complete and watch for premature acceptance.
- Invariant to test: Later-round `public key commitments` data must never satisfy earlier-round `received share` checks.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `keygen(...)`, `reshare(...)`, or `refresh(...)`, let one malicious participant inject conflicting, replayed, or cross-context `public key commitments` data into `insert_identity_if_missing`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
