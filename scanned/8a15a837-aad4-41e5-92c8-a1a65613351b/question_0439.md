# Q439: state record round-trip in state_record::is_contract_code_key

## Question
Can an unprivileged attacker who calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments, controlling state records at their field boundaries, drive `core/primitives/src/state_record.rs::is_contract_code_key` to have a record decode into different state than it encoded, breaking the invariant that state records round-trip exactly, and leading to unintended permanent chain split requiring a hard fork?

## Target
- File/function: `core/primitives/src/state_record.rs` -> `is_contract_code_key`
- Entrypoint: unprivileged attacker calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments
- Attacker controls: state records at their field boundaries
- Exploit idea: have a record decode into different state than it encoded
- Invariant to test: state records round-trip exactly
- Expected Immunefi impact: Critical - unintended permanent chain split requiring a hard fork
- Fast validation: add a proptest/invariant test that randomises the inputs and asserts the accounting identity holds for every generated case
