# Q1996: Leak sensitive state through output

## Question
Can an unprivileged caller and, where needed, a single malicious participant below threshold enter through `lib::reshare(...)` and choose `old_participants`, `new_participants`, `old_threshold`, `new_threshold` so repeated calls to `reshare` expose share-dependent structure in `private share` or `keygen output` that should stay hidden, causing Information disclosure of sensitive MPC state?

## Target
- File/function: `src/lib.rs::reshare`
- Entrypoint: `lib::reshare(...)`
- Attacker controls: `old_participants`, `new_participants`, `old_threshold`, `new_threshold`
- Exploit idea: Query `private share` repeatedly under attacker-chosen inputs and inspect whether the public output leaks share-dependent structure.
- Invariant to test: Public outputs must not leak hidden share-dependent information about `private share` or `keygen output`.
- Expected Immunefi impact: Information disclosure of sensitive MPC state
- Fast validation: Construct a deterministic unit or invariant test around `lib::reshare` that feeds crafted `private share` / `keygen output` inputs, then assert whether downstream verification accepts an output that should have been rejected.
