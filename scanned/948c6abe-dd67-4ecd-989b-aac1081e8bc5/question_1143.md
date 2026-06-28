# Q1143: call() boundary extreme at origin derivation from `predecessor_address`

## Question
Can an attacker craft max, min, zero, or near-overflow transaction values through `call()` on the Aurora engine contract so that origin derivation from `predecessor_address` crosses a boundary the rest of the engine handles differently, breaking direct EVM call entry must preserve the same balance, gas, authorization, and state-commit invariants as transaction submission and causing Insolvency?

## Target
- File/function: `engine/src/contract_methods/evm_transactions.rs::call -> engine/src/engine.rs::call_with_args / call` -> `origin derivation from `predecessor_address``
- Entrypoint: `call()` on the Aurora engine contract
- Attacker controls: borsh `CallArgs`, target contract address, calldata, attached value, and repeated call ordering
- Exploit idea: target zero, max, and overflow-adjacent values at the precise boundary enforced by the subtarget.
- Invariant to test: direct EVM call entry must preserve the same balance, gas, authorization, and state-commit invariants as transaction submission
- Expected Immunefi impact: Insolvency
- Fast validation: Fuzz around zero, one, `u64::MAX`, and `U256` edges for the targeted field while checking post-state and fee accounting. write a Rust integration test that invokes `call()` with crafted `CallArgs`, including edge-case values and calldata, and checks status, logs, balances, and storage
