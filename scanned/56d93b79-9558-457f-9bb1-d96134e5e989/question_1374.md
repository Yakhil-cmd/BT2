# Q1374: deploy_code() delegation gap at promise-log filtering after deployment

## Question
Can an attacker abuse delegated code or authorization semantics through `deploy_code()` on the Aurora engine contract so that promise-log filtering after deployment trusts the wrong code-bearing account state, enabling unauthorized value movement or Permanent freezing of funds?

## Target
- File/function: `engine/src/contract_methods/evm_transactions.rs::deploy_code -> engine/src/engine.rs::deploy_code_with_input / deploy_code` -> `promise-log filtering after deployment`
- Entrypoint: `deploy_code()` on the Aurora engine contract
- Attacker controls: deployment bytecode, constructor input, repeated deployment timing, and any address constraints reachable through the entry path
- Exploit idea: target delegated-account behavior and any code-presence assumptions at the subtarget.
- Invariant to test: contract deployment must charge and commit exactly once, derive the correct address, and never leave half-deployed state behind
- Expected Immunefi impact: Permanent freezing of funds
- Fast validation: Construct delegated and non-delegated sender states around the same logical call and assert auth, fee, and execution behavior stay consistent. write a Rust integration test that deploys crafted bytecode through `deploy_code()`, then checks address derivation, code storage, logs, balances, and revert handling
