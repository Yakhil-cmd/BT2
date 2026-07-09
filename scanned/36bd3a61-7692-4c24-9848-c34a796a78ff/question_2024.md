# Q2024: Split global and local checks

## Question
Can a single malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, or `refresh(...)` and craft `secret`, `old_reshare_package`, `protocol message timing` so each local sub-check inside `assert_keyshare_inputs` accepts its own `domain_separator` fragment, but the combined global statement over `keyshare` is still false and nevertheless accepted, leading to Cryptographic flaws?

## Target
- File/function: `src/dkg.rs::assert_keyshare_inputs`
- Entrypoint: `keygen(...)`, `reshare(...)`, or `refresh(...)`
- Attacker controls: `secret`, `old_reshare_package`, `protocol message timing`
- Exploit idea: Make each local check over `domain_separator` pass independently, then verify whether the combined global statement over `keyshare` is still false but accepted.
- Invariant to test: Local checks on decomposed subparts of `domain_separator` must imply the global algebraic statement, not merely independent fragments.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Run two or more local protocol instances around `keygen(...)`, `reshare(...)`, or `refresh(...)`, let one malicious participant inject conflicting, replayed, or cross-context `domain_separator` data into `assert_keyshare_inputs`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
