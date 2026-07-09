# Q1974: Iterate toward hidden state

## Question
Can an unprivileged caller and, where needed, a single malicious participant below threshold enter through `lib::refresh(...)` and make repeated attacker-chosen queries around `refresh` so the returned `derived verifying key` or `participant set` values reveal linear information about hidden shares or nonce material over time, causing Information disclosure of sensitive MPC state?

## Target
- File/function: `src/lib.rs::refresh`
- Entrypoint: `lib::refresh(...)`
- Attacker controls: `old_participants`, `old_threshold`, `old_public_key`, `old_signing_key`
- Exploit idea: Collect many attacker-chosen outputs that depend on `derived verifying key` and test whether linear relations reveal hidden shares or nonce structure over time.
- Invariant to test: Public-facing return values derived from `derived verifying key` must not allow iterative reconstruction of hidden state across repeated queries.
- Expected Immunefi impact: Information disclosure of sensitive MPC state
- Fast validation: Construct a deterministic unit or invariant test around `lib::refresh` that feeds crafted `derived verifying key` / `participant set` inputs, then assert whether downstream verification accepts an output that should have been rejected.
