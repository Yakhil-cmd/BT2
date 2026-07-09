# Q720: Equivocate per recipient

## Question
Can a single malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, or `refresh(...)` and send recipient-specific `session_id` variants into `public_key_from_commitments` so different honest parties bind different views of `old participant set` yet still converge on an accepted downstream output, leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/dkg.rs::public_key_from_commitments`
- Entrypoint: `keygen(...)`, `reshare(...)`, or `refresh(...)`
- Attacker controls: `commitments`, `protocol message timing`
- Exploit idea: Feed different `session_id` values to different honest parties and test whether `old participant set` still converges without detection.
- Invariant to test: All honest parties must observe one consistent `session_id` / `old participant set` transcript for the same round.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `keygen(...)`, `reshare(...)`, or `refresh(...)`, let one malicious participant inject conflicting, replayed, or cross-context `session_id` data into `public_key_from_commitments`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
