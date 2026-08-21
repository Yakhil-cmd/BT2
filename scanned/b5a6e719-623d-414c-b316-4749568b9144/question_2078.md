# Q2078: global contract identity confusion in global_contract::try_from

## Question
Can an unprivileged attacker who deploys attacker-authored wasm with a `DeployContract` action and then calls it, controlling a global contract deployed by hash versus by account id, drive `core/primitives-core/src/global_contract.rs::try_from` to make an account resolve to different code than the identifier it references, breaking the invariant that a global contract identifier always resolves to exactly one code blob, and leading to unintended permanent chain split requiring a hard fork?

## Target
- File/function: `core/primitives-core/src/global_contract.rs` -> `try_from`
- Entrypoint: unprivileged attacker deploys attacker-authored wasm with a `DeployContract` action and then calls it
- Attacker controls: a global contract deployed by hash versus by account id
- Exploit idea: make an account resolve to different code than the identifier it references
- Invariant to test: a global contract identifier always resolves to exactly one code blob
- Expected Immunefi impact: Critical - unintended permanent chain split requiring a hard fork
- Fast validation: add a case to `runtime/runtime/src/tests/apply.rs` and assert the balance checker and gas totals with `cargo test -p node-runtime --features test_features`
