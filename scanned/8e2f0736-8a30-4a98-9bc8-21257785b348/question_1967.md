# Q1967: Desync batched indices

## Question
Can an unprivileged caller and, where needed, a single malicious participant below threshold enter through `lib::refresh(...)` and use crafted batching inputs in `old_participants`, `old_threshold`, `old_public_key`, `old_signing_key` so `refresh` remaps one party's `public key` to another party's `threshold` through index, row, or column confusion, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/lib.rs::refresh`
- Entrypoint: `lib::refresh(...)`
- Attacker controls: `old_participants`, `old_threshold`, `old_public_key`, `old_signing_key`
- Exploit idea: Exploit array, row, column, or index confusion to remap one participant's `public key` to another.
- Invariant to test: Batched helpers must preserve the original participant-to-`public key` mapping.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `lib::refresh` that feeds crafted `public key` / `threshold` inputs, then assert whether downstream verification accepts an output that should have been rejected.
