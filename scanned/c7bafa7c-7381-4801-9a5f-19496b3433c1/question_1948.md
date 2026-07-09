# Q1948: Iterate toward hidden state

## Question
Can an unprivileged caller and, where needed, a single malicious participant below threshold enter through `lib::keygen(...)` and make repeated attacker-chosen queries around `keygen` so the returned `derived signing share` or `private share` values reveal linear information about hidden shares or nonce material over time, causing Information disclosure of sensitive MPC state?

## Target
- File/function: `src/lib.rs::keygen`
- Entrypoint: `lib::keygen(...)`
- Attacker controls: `participants`, `threshold`
- Exploit idea: Collect many attacker-chosen outputs that depend on `derived signing share` and test whether linear relations reveal hidden shares or nonce structure over time.
- Invariant to test: Public-facing return values derived from `derived signing share` must not allow iterative reconstruction of hidden state across repeated queries.
- Expected Immunefi impact: Information disclosure of sensitive MPC state
- Fast validation: Construct a deterministic unit or invariant test around `lib::keygen` that feeds crafted `derived signing share` / `private share` inputs, then assert whether downstream verification accepts an output that should have been rejected.
