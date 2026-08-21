# Q228: locked balance invariant in account::is_none

## Question
Can an unprivileged attacker who submits `Stake` / `DeleteAccount` / `AddKey` action sequences from its own account, controlling stake and unstake sequences around epoch boundaries, drive `core/primitives-core/src/account.rs::is_none` to make `locked` exceed `amount` or leave value unaccounted, breaking the invariant that `amount` and `locked` are always non-negative and jointly conserved, and leading to direct loss of funds / unauthorized token minting?

## Target
- File/function: `core/primitives-core/src/account.rs` -> `is_none`
- Entrypoint: unprivileged attacker submits `Stake` / `DeleteAccount` / `AddKey` action sequences from its own account
- Attacker controls: stake and unstake sequences around epoch boundaries
- Exploit idea: make `locked` exceed `amount` or leave value unaccounted
- Invariant to test: `amount` and `locked` are always non-negative and jointly conserved
- Expected Immunefi impact: Critical - direct loss of funds / unauthorized token minting
- Fast validation: add a case to `runtime/runtime/src/tests/apply.rs` and assert the balance checker and gas totals with `cargo test -p node-runtime --features test_features`
