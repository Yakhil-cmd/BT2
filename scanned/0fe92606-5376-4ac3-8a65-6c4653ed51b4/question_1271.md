# Q1271: call() nonce window around state application through `apply(values, .., true)`

## Question
Can an attacker use `call()` on the Aurora engine contract to create a nonce window where state application through `apply(values, .., true)` checks one sender nonce but a later path increments or refunds against another, allowing replay, stuck funds, or stale-accounting effects that lead to Permanent freezing of funds?

## Target
- File/function: `engine/src/contract_methods/evm_transactions.rs::call -> engine/src/engine.rs::call_with_args / call` -> `state application through `apply(values, .., true)``
- Entrypoint: `call()` on the Aurora engine contract
- Attacker controls: borsh `CallArgs`, target contract address, calldata, attached value, and repeated call ordering
- Exploit idea: attack nonce freshness and increment timing around the named subtarget.
- Invariant to test: direct EVM call entry must preserve the same balance, gas, authorization, and state-commit invariants as transaction submission
- Expected Immunefi impact: Permanent freezing of funds
- Fast validation: Replay the same signed payload across controlled success, revert, and fatal branches and compare stored nonce and resulting value movement. write a Rust integration test that invokes `call()` with crafted `CallArgs`, including edge-case values and calldata, and checks status, logs, balances, and storage
