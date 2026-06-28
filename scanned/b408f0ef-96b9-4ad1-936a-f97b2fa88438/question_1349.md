# Q1349: deploy_code() call-create ambiguity near used-gas and status handling after `transact_create`

## Question
Can an attacker make used-gas and status handling after `transact_create` misclassify a transaction as a call when it should be a create, or vice versa, through `deploy_code()` on the Aurora engine contract, so the wrong path consumes value or updates state and causes Insolvency?

## Target
- File/function: `engine/src/contract_methods/evm_transactions.rs::deploy_code -> engine/src/engine.rs::deploy_code_with_input / deploy_code` -> `used-gas and status handling after `transact_create``
- Entrypoint: `deploy_code()` on the Aurora engine contract
- Attacker controls: deployment bytecode, constructor input, repeated deployment timing, and any address constraints reachable through the entry path
- Exploit idea: target transaction fields that decide create-versus-call routing around the named subtarget.
- Invariant to test: contract deployment must charge and commit exactly once, derive the correct address, and never leave half-deployed state behind
- Expected Immunefi impact: Insolvency
- Fast validation: Exercise both empty-recipient and non-empty-recipient variants with identical payloads and assert only the intended route mutates code and balances. write a Rust integration test that deploys crafted bytecode through `deploy_code()`, then checks address derivation, code storage, logs, balances, and revert handling
