# Q2043: account field overflow in account::set_locked

## Question
Can an unprivileged attacker who calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments, controlling balances and usage values driven toward the integer bound, drive `core/primitives-core/src/account.rs::set_locked` to overflow an account field into a wrong value, breaking the invariant that account arithmetic is checked and never wraps, and leading to direct loss of funds / unauthorized token minting?

## Target
- File/function: `core/primitives-core/src/account.rs` -> `set_locked`
- Entrypoint: unprivileged attacker calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments
- Attacker controls: balances and usage values driven toward the integer bound
- Exploit idea: overflow an account field into a wrong value
- Invariant to test: account arithmetic is checked and never wraps
- Expected Immunefi impact: Critical - direct loss of funds / unauthorized token minting
- Fast validation: add a proptest/invariant test that randomises the inputs and asserts the accounting identity holds for every generated case
