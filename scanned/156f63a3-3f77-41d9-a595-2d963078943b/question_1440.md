# Q1440: deploy_code() resource stranding after encoding of the created address in `SubmitResult`

## Question
Can an attacker use `deploy_code()` on the Aurora engine contract so that encoding of the created address in `SubmitResult` consumes balance, gas budget, or nonce budget but leaves the corresponding state transition incomplete, stranding user value and causing Temporary freezing of funds?

## Target
- File/function: `engine/src/contract_methods/evm_transactions.rs::deploy_code -> engine/src/engine.rs::deploy_code_with_input / deploy_code` -> `encoding of the created address in `SubmitResult``
- Entrypoint: `deploy_code()` on the Aurora engine contract
- Attacker controls: deployment bytecode, constructor input, repeated deployment timing, and any address constraints reachable through the entry path
- Exploit idea: find a path where the targeted stage consumes a scarce resource before the rest of the transaction meaningfully completes.
- Invariant to test: contract deployment must charge and commit exactly once, derive the correct address, and never leave half-deployed state behind
- Expected Immunefi impact: Temporary freezing of funds
- Fast validation: Force early failure immediately after the targeted step and assert all consumed resources are fully refunded or rolled back. write a Rust integration test that deploys crafted bytecode through `deploy_code()`, then checks address derivation, code storage, logs, balances, and revert handling
