# Q105: Equivocate per recipient

## Question
Can a single malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, or `refresh(...)` and send recipient-specific `domain_separator` variants into `do_reshare` so different honest parties bind different views of `old participant set` yet still converge on an accepted downstream output, leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/dkg.rs::do_reshare`
- Entrypoint: `keygen(...)`, `reshare(...)`, or `refresh(...)`
- Attacker controls: `participants`, `threshold`, `old_participants`, `old_public_key`, `protocol message timing`
- Exploit idea: Feed different `domain_separator` values to different honest parties and test whether `old participant set` still converges without detection.
- Invariant to test: All honest parties must observe one consistent `domain_separator` / `old participant set` transcript for the same round.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `keygen(...)`, `reshare(...)`, or `refresh(...)`, let one malicious participant inject conflicting, replayed, or cross-context `domain_separator` data into `do_reshare`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
