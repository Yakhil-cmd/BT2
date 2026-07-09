# Q70: Split global and local checks

## Question
Can a single malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, or `refresh(...)` and craft `participants`, `threshold`, `protocol message timing` so each local sub-check inside `do_keygen` accepts its own `domain_separator` fragment, but the combined global statement over `domain_separator` is still false and nevertheless accepted, leading to Cryptographic flaws?

## Target
- File/function: `src/dkg.rs::do_keygen`
- Entrypoint: `keygen(...)`, `reshare(...)`, or `refresh(...)`
- Attacker controls: `participants`, `threshold`, `protocol message timing`
- Exploit idea: Make each local check over `domain_separator` pass independently, then verify whether the combined global statement over `domain_separator` is still false but accepted.
- Invariant to test: Local checks on decomposed subparts of `domain_separator` must imply the global algebraic statement, not merely independent fragments.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Run two or more local protocol instances around `keygen(...)`, `reshare(...)`, or `refresh(...)`, let one malicious participant inject conflicting, replayed, or cross-context `domain_separator` data into `do_keygen`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
