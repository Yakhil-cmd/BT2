# Q1156: call() zero-address edge in origin derivation from `predecessor_address`

## Question
Can an attacker hit a zero-address or empty-field edge through `call()` on the Aurora engine contract so that origin derivation from `predecessor_address` routes the transaction differently from the rest of the engine and causes Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield?

## Target
- File/function: `engine/src/contract_methods/evm_transactions.rs::call -> engine/src/engine.rs::call_with_args / call` -> `origin derivation from `predecessor_address``
- Entrypoint: `call()` on the Aurora engine contract
- Attacker controls: borsh `CallArgs`, target contract address, calldata, attached value, and repeated call ordering
- Exploit idea: target the exact empty or zero-valued branch controlled by the subtarget.
- Invariant to test: direct EVM call entry must preserve the same balance, gas, authorization, and state-commit invariants as transaction submission
- Expected Immunefi impact: Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield
- Fast validation: Test empty recipient, zero sender-derived branch, and zero-value variants and assert route selection and state updates stay canonical. write a Rust integration test that invokes `call()` with crafted `CallArgs`, including edge-case values and calldata, and checks status, logs, balances, and storage
