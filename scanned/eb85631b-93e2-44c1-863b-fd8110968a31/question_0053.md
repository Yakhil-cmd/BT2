# Q53: Equivocate per recipient

## Question
Can a single malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, or `refresh(...)` and send recipient-specific `new participant set` variants into `do_keygen` so different honest parties bind different views of `session_id` yet still converge on an accepted downstream output, leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/dkg.rs::do_keygen`
- Entrypoint: `keygen(...)`, `reshare(...)`, or `refresh(...)`
- Attacker controls: `participants`, `threshold`, `protocol message timing`
- Exploit idea: Feed different `new participant set` values to different honest parties and test whether `session_id` still converges without detection.
- Invariant to test: All honest parties must observe one consistent `new participant set` / `session_id` transcript for the same round.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `keygen(...)`, `reshare(...)`, or `refresh(...)`, let one malicious participant inject conflicting, replayed, or cross-context `new participant set` data into `do_keygen`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
