# Q1993: Desync batched indices

## Question
Can an unprivileged caller and, where needed, a single malicious participant below threshold enter through `lib::reshare(...)` and use crafted batching inputs in `old_participants`, `new_participants`, `old_threshold`, `new_threshold` so `reshare` remaps one party's `reshare` to another party's `keygen output` through index, row, or column confusion, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/lib.rs::reshare`
- Entrypoint: `lib::reshare(...)`
- Attacker controls: `old_participants`, `new_participants`, `old_threshold`, `new_threshold`
- Exploit idea: Exploit array, row, column, or index confusion to remap one participant's `reshare` to another.
- Invariant to test: Batched helpers must preserve the original participant-to-`reshare` mapping.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `lib::reshare` that feeds crafted `reshare` / `keygen output` inputs, then assert whether downstream verification accepts an output that should have been rejected.
