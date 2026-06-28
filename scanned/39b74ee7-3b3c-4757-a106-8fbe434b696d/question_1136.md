# Q1136: call() zero-address edge in borsh decoding of `CallArgs`

## Question
Can an attacker hit a zero-address or empty-field edge through `call()` on the Aurora engine contract so that borsh decoding of `CallArgs` routes the transaction differently from the rest of the engine and causes Insolvency?

## Target
- File/function: `engine/src/contract_methods/evm_transactions.rs::call -> engine/src/engine.rs::call_with_args / call` -> `borsh decoding of `CallArgs``
- Entrypoint: `call()` on the Aurora engine contract
- Attacker controls: borsh `CallArgs`, target contract address, calldata, attached value, and repeated call ordering
- Exploit idea: target the exact empty or zero-valued branch controlled by the subtarget.
- Invariant to test: direct EVM call entry must preserve the same balance, gas, authorization, and state-commit invariants as transaction submission
- Expected Immunefi impact: Insolvency
- Fast validation: Test empty recipient, zero sender-derived branch, and zero-value variants and assert route selection and state updates stay canonical. write a Rust integration test that invokes `call()` with crafted `CallArgs`, including edge-case values and calldata, and checks status, logs, balances, and storage
