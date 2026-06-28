# Q1370: deploy_code() fee ceiling gap in promise-log filtering after deployment

## Question
Can an attacker choose gas fields through `deploy_code()` on the Aurora engine contract so that promise-log filtering after deployment enforces one fee ceiling while the later charging or refund path uses another, resulting in free execution or excess balance burn and thus Permanent freezing of funds?

## Target
- File/function: `engine/src/contract_methods/evm_transactions.rs::deploy_code -> engine/src/engine.rs::deploy_code_with_input / deploy_code` -> `promise-log filtering after deployment`
- Entrypoint: `deploy_code()` on the Aurora engine contract
- Attacker controls: deployment bytecode, constructor input, repeated deployment timing, and any address constraints reachable through the entry path
- Exploit idea: split fee-ceiling enforcement from actual gas payment semantics at the targeted stage.
- Invariant to test: contract deployment must charge and commit exactly once, derive the correct address, and never leave half-deployed state behind
- Expected Immunefi impact: Permanent freezing of funds
- Fast validation: Fuzz `max_fee_per_gas`, priority fee, gas limit, and any max-gas-price cap while checking exact sender and relayer deltas. write a Rust integration test that deploys crafted bytecode through `deploy_code()`, then checks address derivation, code storage, logs, balances, and revert handling
