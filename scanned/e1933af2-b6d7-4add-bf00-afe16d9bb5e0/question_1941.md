# Q1941: Desync batched indices

## Question
Can an unprivileged caller and, where needed, a single malicious participant below threshold enter through `lib::keygen(...)` and use crafted batching inputs in `participants`, `threshold` so `keygen` remaps one party's `keygen` to another party's `derived verifying key` through index, row, or column confusion, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/lib.rs::keygen`
- Entrypoint: `lib::keygen(...)`
- Attacker controls: `participants`, `threshold`
- Exploit idea: Exploit array, row, column, or index confusion to remap one participant's `keygen` to another.
- Invariant to test: Batched helpers must preserve the original participant-to-`keygen` mapping.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `lib::keygen` that feeds crafted `keygen` / `derived verifying key` inputs, then assert whether downstream verification accepts an output that should have been rejected.
