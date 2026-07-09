# Q1970: Leak sensitive state through output

## Question
Can an unprivileged caller and, where needed, a single malicious participant below threshold enter through `lib::refresh(...)` and choose `old_participants`, `old_threshold`, `old_public_key`, `old_signing_key` so repeated calls to `refresh` expose share-dependent structure in `keygen output` or `public key` that should stay hidden, causing Information disclosure of sensitive MPC state?

## Target
- File/function: `src/lib.rs::refresh`
- Entrypoint: `lib::refresh(...)`
- Attacker controls: `old_participants`, `old_threshold`, `old_public_key`, `old_signing_key`
- Exploit idea: Query `keygen output` repeatedly under attacker-chosen inputs and inspect whether the public output leaks share-dependent structure.
- Invariant to test: Public outputs must not leak hidden share-dependent information about `keygen output` or `public key`.
- Expected Immunefi impact: Information disclosure of sensitive MPC state
- Fast validation: Construct a deterministic unit or invariant test around `lib::refresh` that feeds crafted `keygen output` / `public key` inputs, then assert whether downstream verification accepts an output that should have been rejected.
