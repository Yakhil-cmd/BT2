# Q441: state record round-trip in state_record::state_record_to_shard_id

## Question
Can an unprivileged attacker who calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments, controlling state records at their field boundaries, drive `core/primitives/src/state_record.rs::state_record_to_shard_id` to have a record decode into different state than it encoded, breaking the invariant that state records round-trip exactly, and leading to unintended permanent chain split requiring a hard fork?

## Target
- File/function: `core/primitives/src/state_record.rs` -> `state_record_to_shard_id`
- Entrypoint: unprivileged attacker calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments
- Attacker controls: state records at their field boundaries
- Exploit idea: have a record decode into different state than it encoded
- Invariant to test: state records round-trip exactly
- Expected Immunefi impact: Critical - unintended permanent chain split requiring a hard fork
- Fast validation: add a proptest/invariant test that randomises the inputs and asserts the accounting identity holds for every generated case
