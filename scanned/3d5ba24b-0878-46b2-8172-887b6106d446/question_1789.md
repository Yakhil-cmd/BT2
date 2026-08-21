# Q1789: yield-timeout accounting in types::get_potentially_expired_transactions_and_expiration_flags

## Question
Can an unprivileged attacker who calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments, controlling many yielded promises timed to expire in the same chunk, drive `runtime/runtime/src/types.rs::get_potentially_expired_transactions_and_expiration_flags` to force unbounded timeout processing in a single chunk, breaking the invariant that timeout processing per chunk is bounded and gas-charged, and leading to network unable to confirm new transactions (shard/chain halt)?

## Target
- File/function: `runtime/runtime/src/types.rs` -> `get_potentially_expired_transactions_and_expiration_flags`
- Entrypoint: unprivileged attacker calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments
- Attacker controls: many yielded promises timed to expire in the same chunk
- Exploit idea: force unbounded timeout processing in a single chunk
- Invariant to test: timeout processing per chunk is bounded and gas-charged
- Expected Immunefi impact: Critical - network unable to confirm new transactions (shard/chain halt)
- Fast validation: add a case to `runtime/runtime/src/tests/apply.rs` and assert the balance checker and gas totals with `cargo test -p node-runtime --features test_features`
