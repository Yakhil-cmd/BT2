# Q726: Substitute app or public key

## Question
Can a single malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, or `refresh(...)` and swap `received share` for attacker-chosen `session_id` while keeping the rest of `commitments`, `protocol message timing` valid enough that `public_key_from_commitments` produces an accepted unauthorized output, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/dkg.rs::public_key_from_commitments`
- Entrypoint: `keygen(...)`, `reshare(...)`, or `refresh(...)`
- Attacker controls: `commitments`, `protocol message timing`
- Exploit idea: Substitute application/public-key context late in the flow and check whether the output remains acceptable to downstream verifiers.
- Invariant to test: `received share` outputs must be bound to the exact `session_id` selected by the honest protocol run.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `keygen(...)`, `reshare(...)`, or `refresh(...)`, let one malicious participant inject conflicting, replayed, or cross-context `received share` data into `public_key_from_commitments`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
