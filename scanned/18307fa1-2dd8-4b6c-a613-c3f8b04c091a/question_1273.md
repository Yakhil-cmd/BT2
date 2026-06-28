# Q1273: call() status-state split after state application through `apply(values, .., true)`

## Question
Can an attacker make state application through `apply(values, .., true)` return a status that looks like a clean failure while state, logs, or refunds have already moved in a way that can be exploited for Insolvency?

## Target
- File/function: `engine/src/contract_methods/evm_transactions.rs::call -> engine/src/engine.rs::call_with_args / call` -> `state application through `apply(values, .., true)``
- Entrypoint: `call()` on the Aurora engine contract
- Attacker controls: borsh `CallArgs`, target contract address, calldata, attached value, and repeated call ordering
- Exploit idea: force a divergence between the reported transaction status and the actual state side effects after the named subtarget.
- Invariant to test: direct EVM call entry must preserve the same balance, gas, authorization, and state-commit invariants as transaction submission
- Expected Immunefi impact: Insolvency
- Fast validation: Compare returned `SubmitResult.status` with balances, logs, and storage after crafted reverts and fatal exits. write a Rust integration test that invokes `call()` with crafted `CallArgs`, including edge-case values and calldata, and checks status, logs, balances, and storage
