# Q2874: promise api argument abuse in logic::current_contract_code

## Question
Can an unprivileged attacker who runs an attacker contract that emits receipts via `promise_batch_action_*` host calls, controlling promise indexes, ids and counts outside their valid range, drive `runtime/near-vm-runner/src/logic/logic.rs::current_contract_code` to index a promise slot that does not belong to the current call, breaking the invariant that promise indexes are validated against the current call's promise set, and leading to unauthorized state modification of an account the attacker does not control?

## Target
- File/function: `runtime/near-vm-runner/src/logic/logic.rs` -> `current_contract_code`
- Entrypoint: unprivileged attacker runs an attacker contract that emits receipts via `promise_batch_action_*` host calls
- Attacker controls: promise indexes, ids and counts outside their valid range
- Exploit idea: index a promise slot that does not belong to the current call
- Invariant to test: promise indexes are validated against the current call's promise set
- Expected Immunefi impact: Critical - unauthorized state modification of an account the attacker does not control
- Fast validation: add a case under `runtime/near-vm-runner/src/tests/` and diff burnt gas / outcome against the expected costs
