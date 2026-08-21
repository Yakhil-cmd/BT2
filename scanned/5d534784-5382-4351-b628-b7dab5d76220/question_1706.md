# Q1706: global contract deletion in global_contracts::check_and_update_nonce

## Question
Can an unprivileged attacker who deploys attacker-authored wasm with a `DeployContract` action and then calls it, controlling references to a global contract that the attacker then makes unreachable, drive `runtime/runtime/src/global_contracts.rs::check_and_update_nonce` to brick every account referencing shared code, breaking the invariant that code referenced by a live account always remains available, and leading to permanent freezing of funds?

## Target
- File/function: `runtime/runtime/src/global_contracts.rs` -> `check_and_update_nonce`
- Entrypoint: unprivileged attacker deploys attacker-authored wasm with a `DeployContract` action and then calls it
- Attacker controls: references to a global contract that the attacker then makes unreachable
- Exploit idea: brick every account referencing shared code
- Invariant to test: code referenced by a live account always remains available
- Expected Immunefi impact: Critical - permanent freezing of funds
- Fast validation: add a case to `runtime/runtime/src/tests/apply.rs` and assert the balance checker and gas totals with `cargo test -p node-runtime --features test_features`
