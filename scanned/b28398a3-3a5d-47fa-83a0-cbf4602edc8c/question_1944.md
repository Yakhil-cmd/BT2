# Q1944: Leak sensitive state through output

## Question
Can an unprivileged caller and, where needed, a single malicious participant below threshold enter through `lib::keygen(...)` and choose `participants`, `threshold` so repeated calls to `keygen` expose share-dependent structure in `keygen output` or `keygen output` that should stay hidden, causing Information disclosure of sensitive MPC state?

## Target
- File/function: `src/lib.rs::keygen`
- Entrypoint: `lib::keygen(...)`
- Attacker controls: `participants`, `threshold`
- Exploit idea: Query `keygen output` repeatedly under attacker-chosen inputs and inspect whether the public output leaks share-dependent structure.
- Invariant to test: Public outputs must not leak hidden share-dependent information about `keygen output` or `keygen output`.
- Expected Immunefi impact: Information disclosure of sensitive MPC state
- Fast validation: Construct a deterministic unit or invariant test around `lib::keygen` that feeds crafted `keygen output` / `keygen output` inputs, then assert whether downstream verification accepts an output that should have been rejected.
