# Q3897: receipt id collision in actions::receipt_required_cost

## Question
Can an unprivileged attacker who runs an attacker contract that emits receipts via `promise_batch_action_*` host calls, controlling the action index, predecessor id and nonce feeding receipt id derivation, drive `runtime/runtime/src/actions.rs::receipt_required_cost` to produce two distinct receipts sharing one receipt id so one outcome overwrites the other, breaking the invariant that receipt ids are unique across all receipts ever produced, and leading to direct loss of funds / unauthorized token minting?

## Target
- File/function: `runtime/runtime/src/actions.rs` -> `receipt_required_cost`
- Entrypoint: unprivileged attacker runs an attacker contract that emits receipts via `promise_batch_action_*` host calls
- Attacker controls: the action index, predecessor id and nonce feeding receipt id derivation
- Exploit idea: produce two distinct receipts sharing one receipt id so one outcome overwrites the other
- Invariant to test: receipt ids are unique across all receipts ever produced
- Expected Immunefi impact: Critical - direct loss of funds / unauthorized token minting
- Fast validation: add a case to `runtime/runtime/src/tests/apply.rs` and assert the balance checker and gas totals with `cargo test -p node-runtime --features test_features`
