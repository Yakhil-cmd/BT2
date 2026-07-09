# Q1999: Split global and local checks

## Question
Can an unprivileged caller and, where needed, a single malicious participant below threshold enter through `lib::reshare(...)` and craft `old_participants`, `new_participants`, `old_threshold`, `new_threshold` so each local sub-check inside `reshare` accepts its own `private share` fragment, but the combined global statement over `threshold` is still false and nevertheless accepted, leading to Cryptographic flaws?

## Target
- File/function: `src/lib.rs::reshare`
- Entrypoint: `lib::reshare(...)`
- Attacker controls: `old_participants`, `new_participants`, `old_threshold`, `new_threshold`
- Exploit idea: Make each local check over `private share` pass independently, then verify whether the combined global statement over `threshold` is still false but accepted.
- Invariant to test: Local checks on decomposed subparts of `private share` must imply the global algebraic statement, not merely independent fragments.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Construct a deterministic unit or invariant test around `lib::reshare` that feeds crafted `private share` / `threshold` inputs, then assert whether downstream verification accepts an output that should have been rejected.
