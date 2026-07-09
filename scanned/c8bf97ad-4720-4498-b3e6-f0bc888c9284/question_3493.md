# Q3493: Split global and local checks

## Question
Can an unprivileged caller and, where needed, a single malicious participant below threshold enter through `lib::derive_verifying_key(...)` and craft `public_key` so each local sub-check inside `derive_verifying_key` accepts its own `derived verifying key` fragment, but the combined global statement over `derived signing share` is still false and nevertheless accepted, leading to Cryptographic flaws?

## Target
- File/function: `src/lib.rs::derive_verifying_key`
- Entrypoint: `lib::derive_verifying_key(...)`
- Attacker controls: `public_key`
- Exploit idea: Make each local check over `derived verifying key` pass independently, then verify whether the combined global statement over `derived signing share` is still false but accepted.
- Invariant to test: Local checks on decomposed subparts of `derived verifying key` must imply the global algebraic statement, not merely independent fragments.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Construct a deterministic unit or invariant test around `lib::derive_verifying_key` that feeds crafted `derived verifying key` / `derived signing share` inputs, then assert whether downstream verification accepts an output that should have been rejected.
