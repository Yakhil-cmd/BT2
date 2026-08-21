# Q1104: context field spoofing in dependencies::get_receipt_receiver

## Question
Can an unprivileged attacker who calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments, controlling the call chain that populates the execution context, drive `runtime/near-vm-runner/src/logic/dependencies.rs::get_receipt_receiver` to observe a context field that misrepresents the real caller or block, breaking the invariant that context fields always reflect the true receipt and block state, and leading to unauthorized state modification of an account the attacker does not control?

## Target
- File/function: `runtime/near-vm-runner/src/logic/dependencies.rs` -> `get_receipt_receiver`
- Entrypoint: unprivileged attacker calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments
- Attacker controls: the call chain that populates the execution context
- Exploit idea: observe a context field that misrepresents the real caller or block
- Invariant to test: context fields always reflect the true receipt and block state
- Expected Immunefi impact: Critical - unauthorized state modification of an account the attacker does not control
- Fast validation: add a case under `runtime/near-vm-runner/src/tests/` and diff burnt gas / outcome against the expected costs
