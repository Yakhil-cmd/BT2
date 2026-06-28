# Q1383: deploy_code() boundary extreme at state application after create success or failure

## Question
Can an attacker craft max, min, zero, or near-overflow transaction values through `deploy_code()` on the Aurora engine contract so that state application after create success or failure crosses a boundary the rest of the engine handles differently, breaking contract deployment must charge and commit exactly once, derive the correct address, and never leave half-deployed state behind and causing Insolvency?

## Target
- File/function: `engine/src/contract_methods/evm_transactions.rs::deploy_code -> engine/src/engine.rs::deploy_code_with_input / deploy_code` -> `state application after create success or failure`
- Entrypoint: `deploy_code()` on the Aurora engine contract
- Attacker controls: deployment bytecode, constructor input, repeated deployment timing, and any address constraints reachable through the entry path
- Exploit idea: target zero, max, and overflow-adjacent values at the precise boundary enforced by the subtarget.
- Invariant to test: contract deployment must charge and commit exactly once, derive the correct address, and never leave half-deployed state behind
- Expected Immunefi impact: Insolvency
- Fast validation: Fuzz around zero, one, `u64::MAX`, and `U256` edges for the targeted field while checking post-state and fee accounting. write a Rust integration test that deploys crafted bytecode through `deploy_code()`, then checks address derivation, code storage, logs, balances, and revert handling
