# Q1984: Mismatch commitment and share

## Question
Can an unprivileged caller and, where needed, a single malicious participant below threshold enter through `lib::reshare(...)` and pair a valid-looking `derived verifying key` with a different `derived signing share` reveal so `reshare` checks each piece in isolation but never the combined statement, causing Cryptographic flaws?

## Target
- File/function: `src/lib.rs::reshare`
- Entrypoint: `lib::reshare(...)`
- Attacker controls: `old_participants`, `new_participants`, `old_threshold`, `new_threshold`
- Exploit idea: Commit to one `derived verifying key` and reveal another `derived signing share` that still satisfies separate local checks.
- Invariant to test: A commitment and its corresponding `derived verifying key` reveal must be validated as the same statement.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Construct a deterministic unit or invariant test around `lib::reshare` that feeds crafted `derived verifying key` / `derived signing share` inputs, then assert whether downstream verification accepts an output that should have been rejected.
