# Q3490: Leak sensitive state through output

## Question
Can an unprivileged caller and, where needed, a single malicious participant below threshold enter through `lib::derive_verifying_key(...)` and choose `public_key` so repeated calls to `derive_verifying_key` expose share-dependent structure in `derive` or `public key` that should stay hidden, causing Information disclosure of sensitive MPC state?

## Target
- File/function: `src/lib.rs::derive_verifying_key`
- Entrypoint: `lib::derive_verifying_key(...)`
- Attacker controls: `public_key`
- Exploit idea: Query `derive` repeatedly under attacker-chosen inputs and inspect whether the public output leaks share-dependent structure.
- Invariant to test: Public outputs must not leak hidden share-dependent information about `derive` or `public key`.
- Expected Immunefi impact: Information disclosure of sensitive MPC state
- Fast validation: Construct a deterministic unit or invariant test around `lib::derive_verifying_key` that feeds crafted `derive` / `public key` inputs, then assert whether downstream verification accepts an output that should have been rejected.
