# Q2588: Equivocate per recipient

## Question
Can a single malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, or `refresh(...)` and send recipient-specific `coefficient commitment` variants into `broadcast_success` so different honest parties bind different views of `domain_separator` yet still converge on an accepted downstream output, leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/dkg.rs::broadcast_success`
- Entrypoint: `keygen(...)`, `reshare(...)`, or `refresh(...)`
- Attacker controls: `participants`, `session_id`, `protocol message timing`
- Exploit idea: Feed different `coefficient commitment` values to different honest parties and test whether `domain_separator` still converges without detection.
- Invariant to test: All honest parties must observe one consistent `coefficient commitment` / `domain_separator` transcript for the same round.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `keygen(...)`, `reshare(...)`, or `refresh(...)`, let one malicious participant inject conflicting, replayed, or cross-context `coefficient commitment` data into `broadcast_success`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
