# Q315: re-init after delete in universal_account_id::hrp_expanded

## Question
Can an unprivileged attacker who creates implicit or deterministic accounts by transferring to attacker-derived account ids, controlling delete then recreate cycles on one derived id, drive `core/primitives-core/src/universal_account_id.rs::hrp_expanded` to resurrect an account id with attacker-chosen state or keys, breaking the invariant that recreating a deleted derived id yields the same committed state and keys, and leading to unauthorized state modification of an account the attacker does not control?

## Target
- File/function: `core/primitives-core/src/universal_account_id.rs` -> `hrp_expanded`
- Entrypoint: unprivileged attacker creates implicit or deterministic accounts by transferring to attacker-derived account ids
- Attacker controls: delete then recreate cycles on one derived id
- Exploit idea: resurrect an account id with attacker-chosen state or keys
- Invariant to test: recreating a deleted derived id yields the same committed state and keys
- Expected Immunefi impact: Critical - unauthorized state modification of an account the attacker does not control
- Fast validation: add a case to `runtime/runtime/src/tests/apply.rs` and assert the balance checker and gas totals with `cargo test -p node-runtime --features test_features`
