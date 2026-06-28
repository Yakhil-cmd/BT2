# Q1433: deploy_code() status-state split after encoding of the created address in `SubmitResult`

## Question
Can an attacker make encoding of the created address in `SubmitResult` return a status that looks like a clean failure while state, logs, or refunds have already moved in a way that can be exploited for Insolvency?

## Target
- File/function: `engine/src/contract_methods/evm_transactions.rs::deploy_code -> engine/src/engine.rs::deploy_code_with_input / deploy_code` -> `encoding of the created address in `SubmitResult``
- Entrypoint: `deploy_code()` on the Aurora engine contract
- Attacker controls: deployment bytecode, constructor input, repeated deployment timing, and any address constraints reachable through the entry path
- Exploit idea: force a divergence between the reported transaction status and the actual state side effects after the named subtarget.
- Invariant to test: contract deployment must charge and commit exactly once, derive the correct address, and never leave half-deployed state behind
- Expected Immunefi impact: Insolvency
- Fast validation: Compare returned `SubmitResult.status` with balances, logs, and storage after crafted reverts and fatal exits. write a Rust integration test that deploys crafted bytecode through `deploy_code()`, then checks address derivation, code storage, logs, balances, and revert handling
