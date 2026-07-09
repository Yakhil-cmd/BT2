# Q1947: Split global and local checks

## Question
Can an unprivileged caller and, where needed, a single malicious participant below threshold enter through `lib::keygen(...)` and craft `participants`, `threshold` so each local sub-check inside `keygen` accepts its own `derived verifying key` fragment, but the combined global statement over `participant set` is still false and nevertheless accepted, leading to Cryptographic flaws?

## Target
- File/function: `src/lib.rs::keygen`
- Entrypoint: `lib::keygen(...)`
- Attacker controls: `participants`, `threshold`
- Exploit idea: Make each local check over `derived verifying key` pass independently, then verify whether the combined global statement over `participant set` is still false but accepted.
- Invariant to test: Local checks on decomposed subparts of `derived verifying key` must imply the global algebraic statement, not merely independent fragments.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Construct a deterministic unit or invariant test around `lib::keygen` that feeds crafted `derived verifying key` / `participant set` inputs, then assert whether downstream verification accepts an output that should have been rejected.
