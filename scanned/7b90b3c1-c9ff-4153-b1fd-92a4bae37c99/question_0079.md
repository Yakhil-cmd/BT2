# Q79: Equivocate per recipient

## Question
Can a single malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, or `refresh(...)` and send recipient-specific `old participant set` variants into `do_keyshare` so different honest parties bind different views of `old participant set` yet still converge on an accepted downstream output, leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/dkg.rs::do_keyshare`
- Entrypoint: `keygen(...)`, `reshare(...)`, or `refresh(...)`
- Attacker controls: `participants`, `threshold`, `secret`, `old_reshare_package`, `protocol message timing`
- Exploit idea: Feed different `old participant set` values to different honest parties and test whether `old participant set` still converges without detection.
- Invariant to test: All honest parties must observe one consistent `old participant set` / `old participant set` transcript for the same round.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `keygen(...)`, `reshare(...)`, or `refresh(...)`, let one malicious participant inject conflicting, replayed, or cross-context `old participant set` data into `do_keyshare`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
