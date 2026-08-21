# Q2329: deletion handling in delta::from_raw_key_value

## Question
Can an unprivileged attacker who calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments, controlling delete-then-read sequences across delta boundaries, drive `core/store/src/flat/delta.rs::from_raw_key_value` to observe a deleted value as still present, breaking the invariant that a deleted key is absent in every consistent view, and leading to unauthorized state modification of an account the attacker does not control?

## Target
- File/function: `core/store/src/flat/delta.rs` -> `from_raw_key_value`
- Entrypoint: unprivileged attacker calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments
- Attacker controls: delete-then-read sequences across delta boundaries
- Exploit idea: observe a deleted value as still present
- Invariant to test: a deleted key is absent in every consistent view
- Expected Immunefi impact: Critical - unauthorized state modification of an account the attacker does not control
- Fast validation: run the same chunk through both execution paths and assert identical state root, gas burnt and outcome ids
