# Q3467: Split global and local checks

## Question
Can an unprivileged caller and, where needed, a single malicious participant below threshold enter through `lib::derive_signing_share(...)` and craft `private_share` so each local sub-check inside `derive_signing_share` accepts its own `derived verifying key` fragment, but the combined global statement over `threshold` is still false and nevertheless accepted, leading to Cryptographic flaws?

## Target
- File/function: `src/lib.rs::derive_signing_share`
- Entrypoint: `lib::derive_signing_share(...)`
- Attacker controls: `private_share`
- Exploit idea: Make each local check over `derived verifying key` pass independently, then verify whether the combined global statement over `threshold` is still false but accepted.
- Invariant to test: Local checks on decomposed subparts of `derived verifying key` must imply the global algebraic statement, not merely independent fragments.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Construct a deterministic unit or invariant test around `lib::derive_signing_share` that feeds crafted `derived verifying key` / `threshold` inputs, then assert whether downstream verification accepts an output that should have been rejected.
