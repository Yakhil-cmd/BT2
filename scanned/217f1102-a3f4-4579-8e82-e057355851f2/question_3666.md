# Q3666: state after trap in logic::check_can_add_a_log_message

## Question
Can an unprivileged attacker who calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments, controlling a call that traps after partial host side effects, drive `runtime/near-vm-runner/src/logic/logic.rs::check_can_add_a_log_message` to leave host side effects behind after a trap, breaking the invariant that a trapped execution commits no state, logs or receipts, and leading to unauthorized state modification of an account the attacker does not control?

## Target
- File/function: `runtime/near-vm-runner/src/logic/logic.rs` -> `check_can_add_a_log_message`
- Entrypoint: unprivileged attacker calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments
- Attacker controls: a call that traps after partial host side effects
- Exploit idea: leave host side effects behind after a trap
- Invariant to test: a trapped execution commits no state, logs or receipts
- Expected Immunefi impact: Critical - unauthorized state modification of an account the attacker does not control
- Fast validation: add a case under `runtime/near-vm-runner/src/tests/` and diff burnt gas / outcome against the expected costs
