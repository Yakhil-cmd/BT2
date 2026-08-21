# Q3353: free derived state in deterministic_account_id::action_deterministic_state_init

## Question
Can an unprivileged attacker who creates implicit or deterministic accounts by transferring to attacker-derived account ids, controlling state-init size versus the fee charged for the creating action, drive `runtime/runtime/src/deterministic_account_id.rs::action_deterministic_state_init` to initialise account state without paying its storage cost, breaking the invariant that initial account state is charged at the configured storage price, and leading to greatly increasing the computational cost of the network (free or underpriced execution)?

## Target
- File/function: `runtime/runtime/src/deterministic_account_id.rs` -> `action_deterministic_state_init`
- Entrypoint: unprivileged attacker creates implicit or deterministic accounts by transferring to attacker-derived account ids
- Attacker controls: state-init size versus the fee charged for the creating action
- Exploit idea: initialise account state without paying its storage cost
- Invariant to test: initial account state is charged at the configured storage price
- Expected Immunefi impact: High - greatly increasing the computational cost of the network (free or underpriced execution)
- Fast validation: add a case to `runtime/runtime/src/tests/apply.rs` and assert the balance checker and gas totals with `cargo test -p node-runtime --features test_features`
