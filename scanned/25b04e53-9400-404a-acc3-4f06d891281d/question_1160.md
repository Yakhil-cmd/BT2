# Q1160: call() resource stranding after origin derivation from `predecessor_address`

## Question
Can an attacker use `call()` on the Aurora engine contract so that origin derivation from `predecessor_address` consumes balance, gas budget, or nonce budget but leaves the corresponding state transition incomplete, stranding user value and causing Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield?

## Target
- File/function: `engine/src/contract_methods/evm_transactions.rs::call -> engine/src/engine.rs::call_with_args / call` -> `origin derivation from `predecessor_address``
- Entrypoint: `call()` on the Aurora engine contract
- Attacker controls: borsh `CallArgs`, target contract address, calldata, attached value, and repeated call ordering
- Exploit idea: find a path where the targeted stage consumes a scarce resource before the rest of the transaction meaningfully completes.
- Invariant to test: direct EVM call entry must preserve the same balance, gas, authorization, and state-commit invariants as transaction submission
- Expected Immunefi impact: Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield
- Fast validation: Force early failure immediately after the targeted step and assert all consumed resources are fully refunded or rolled back. write a Rust integration test that invokes `call()` with crafted `CallArgs`, including edge-case values and calldata, and checks status, logs, balances, and storage
