# Q1296: deploy_code() zero-address edge in deployment input forwarding into `deploy_code_with_input`

## Question
Can an attacker hit a zero-address or empty-field edge through `deploy_code()` on the Aurora engine contract so that deployment input forwarding into `deploy_code_with_input` routes the transaction differently from the rest of the engine and causes Insolvency?

## Target
- File/function: `engine/src/contract_methods/evm_transactions.rs::deploy_code -> engine/src/engine.rs::deploy_code_with_input / deploy_code` -> `deployment input forwarding into `deploy_code_with_input``
- Entrypoint: `deploy_code()` on the Aurora engine contract
- Attacker controls: deployment bytecode, constructor input, repeated deployment timing, and any address constraints reachable through the entry path
- Exploit idea: target the exact empty or zero-valued branch controlled by the subtarget.
- Invariant to test: contract deployment must charge and commit exactly once, derive the correct address, and never leave half-deployed state behind
- Expected Immunefi impact: Insolvency
- Fast validation: Test empty recipient, zero sender-derived branch, and zero-value variants and assert route selection and state updates stay canonical. write a Rust integration test that deploys crafted bytecode through `deploy_code()`, then checks address derivation, code storage, logs, balances, and revert handling
