# Q255: front-run derived account in deterministic_account_id::version

## Question
Can an unprivileged attacker who creates implicit or deterministic accounts by transferring to attacker-derived account ids, controlling the derived id and the ordering of the creating transactions, drive `core/primitives-core/src/deterministic_account_id.rs::version` to occupy a deterministic account id before its intended owner claims it, breaking the invariant that only the intended owner can claim an account derived from their inputs, and leading to permanent freezing of funds?

## Target
- File/function: `core/primitives-core/src/deterministic_account_id.rs` -> `version`
- Entrypoint: unprivileged attacker creates implicit or deterministic accounts by transferring to attacker-derived account ids
- Attacker controls: the derived id and the ordering of the creating transactions
- Exploit idea: occupy a deterministic account id before its intended owner claims it
- Invariant to test: only the intended owner can claim an account derived from their inputs
- Expected Immunefi impact: Critical - permanent freezing of funds
- Fast validation: add a case to `runtime/runtime/src/tests/apply.rs` and assert the balance checker and gas totals with `cargo test -p node-runtime --features test_features`
