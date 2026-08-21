# Q3386: cross-contract predecessor in ext::protocol_version

## Question
Can an unprivileged attacker who runs an attacker contract that emits receipts via `promise_batch_action_*` host calls, controlling a chain of calls through intermediary contracts, drive `runtime/runtime/src/ext.rs::protocol_version` to present a forged `predecessor_account_id` to the callee, breaking the invariant that `predecessor_account_id` always equals the direct caller of the receipt, and leading to unauthorized state modification of an account the attacker does not control?

## Target
- File/function: `runtime/runtime/src/ext.rs` -> `protocol_version`
- Entrypoint: unprivileged attacker runs an attacker contract that emits receipts via `promise_batch_action_*` host calls
- Attacker controls: a chain of calls through intermediary contracts
- Exploit idea: present a forged `predecessor_account_id` to the callee
- Invariant to test: `predecessor_account_id` always equals the direct caller of the receipt
- Expected Immunefi impact: Critical - unauthorized state modification of an account the attacker does not control
- Fast validation: add a case under `runtime/near-vm-runner/src/tests/` and diff burnt gas / outcome against the expected costs
