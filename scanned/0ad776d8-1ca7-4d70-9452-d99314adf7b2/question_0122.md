# Q122: Split global and local checks

## Question
Can a single malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, or `refresh(...)` and craft `participants`, `threshold`, `old_participants`, `old_public_key`, `protocol message timing` so each local sub-check inside `do_reshare` accepts its own `reshare` fragment, but the combined global statement over `old participant set` is still false and nevertheless accepted, leading to Cryptographic flaws?

## Target
- File/function: `src/dkg.rs::do_reshare`
- Entrypoint: `keygen(...)`, `reshare(...)`, or `refresh(...)`
- Attacker controls: `participants`, `threshold`, `old_participants`, `old_public_key`, `protocol message timing`
- Exploit idea: Make each local check over `reshare` pass independently, then verify whether the combined global statement over `old participant set` is still false but accepted.
- Invariant to test: Local checks on decomposed subparts of `reshare` must imply the global algebraic statement, not merely independent fragments.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Run two or more local protocol instances around `keygen(...)`, `reshare(...)`, or `refresh(...)`, let one malicious participant inject conflicting, replayed, or cross-context `reshare` data into `do_reshare`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
