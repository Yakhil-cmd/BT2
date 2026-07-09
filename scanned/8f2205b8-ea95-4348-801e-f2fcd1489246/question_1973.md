# Q1973: Split global and local checks

## Question
Can an unprivileged caller and, where needed, a single malicious participant below threshold enter through `lib::refresh(...)` and craft `old_participants`, `old_threshold`, `old_public_key`, `old_signing_key` so each local sub-check inside `refresh` accepts its own `participant set` fragment, but the combined global statement over `keygen output` is still false and nevertheless accepted, leading to Cryptographic flaws?

## Target
- File/function: `src/lib.rs::refresh`
- Entrypoint: `lib::refresh(...)`
- Attacker controls: `old_participants`, `old_threshold`, `old_public_key`, `old_signing_key`
- Exploit idea: Make each local check over `participant set` pass independently, then verify whether the combined global statement over `keygen output` is still false but accepted.
- Invariant to test: Local checks on decomposed subparts of `participant set` must imply the global algebraic statement, not merely independent fragments.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Construct a deterministic unit or invariant test around `lib::refresh` that feeds crafted `participant set` / `keygen output` inputs, then assert whether downstream verification accepts an output that should have been rejected.
