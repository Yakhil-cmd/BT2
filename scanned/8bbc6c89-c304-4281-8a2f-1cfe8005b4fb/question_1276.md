# Q1276: call() zero-address edge in state application through `apply(values, .., true)`

## Question
Can an attacker hit a zero-address or empty-field edge through `call()` on the Aurora engine contract so that state application through `apply(values, .., true)` routes the transaction differently from the rest of the engine and causes Temporary freezing of funds?

## Target
- File/function: `engine/src/contract_methods/evm_transactions.rs::call -> engine/src/engine.rs::call_with_args / call` -> `state application through `apply(values, .., true)``
- Entrypoint: `call()` on the Aurora engine contract
- Attacker controls: borsh `CallArgs`, target contract address, calldata, attached value, and repeated call ordering
- Exploit idea: target the exact empty or zero-valued branch controlled by the subtarget.
- Invariant to test: direct EVM call entry must preserve the same balance, gas, authorization, and state-commit invariants as transaction submission
- Expected Immunefi impact: Temporary freezing of funds
- Fast validation: Test empty recipient, zero sender-derived branch, and zero-value variants and assert route selection and state updates stay canonical. write a Rust integration test that invokes `call()` with crafted `CallArgs`, including edge-case values and calldata, and checks status, logs, balances, and storage
