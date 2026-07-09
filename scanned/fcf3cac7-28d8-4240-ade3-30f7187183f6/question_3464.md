# Q3464: Leak sensitive state through output

## Question
Can an unprivileged caller and, where needed, a single malicious participant below threshold enter through `lib::derive_signing_share(...)` and choose `private_share` so repeated calls to `derive_signing_share` expose share-dependent structure in `derive` or `participant set` that should stay hidden, causing Information disclosure of sensitive MPC state?

## Target
- File/function: `src/lib.rs::derive_signing_share`
- Entrypoint: `lib::derive_signing_share(...)`
- Attacker controls: `private_share`
- Exploit idea: Query `derive` repeatedly under attacker-chosen inputs and inspect whether the public output leaks share-dependent structure.
- Invariant to test: Public outputs must not leak hidden share-dependent information about `derive` or `participant set`.
- Expected Immunefi impact: Information disclosure of sensitive MPC state
- Fast validation: Construct a deterministic unit or invariant test around `lib::derive_signing_share` that feeds crafted `derive` / `participant set` inputs, then assert whether downstream verification accepts an output that should have been rejected.
