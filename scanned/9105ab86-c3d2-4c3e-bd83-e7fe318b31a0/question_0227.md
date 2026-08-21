# Q227: code hash lifecycle in account::is_local

## Question
Can an unprivileged attacker who deploys attacker-authored wasm with a `DeployContract` action and then calls it, controlling deploy, delete and redeploy cycles including global contract references, drive `core/primitives-core/src/account.rs::is_local` to leave an account pointing at code that no longer exists, breaking the invariant that an account's code hash always resolves to stored code, and leading to permanent freezing of funds?

## Target
- File/function: `core/primitives-core/src/account.rs` -> `is_local`
- Entrypoint: unprivileged attacker deploys attacker-authored wasm with a `DeployContract` action and then calls it
- Attacker controls: deploy, delete and redeploy cycles including global contract references
- Exploit idea: leave an account pointing at code that no longer exists
- Invariant to test: an account's code hash always resolves to stored code
- Expected Immunefi impact: Critical - permanent freezing of funds
- Fast validation: add a case to `runtime/runtime/src/tests/apply.rs` and assert the balance checker and gas totals with `cargo test -p node-runtime --features test_features`
