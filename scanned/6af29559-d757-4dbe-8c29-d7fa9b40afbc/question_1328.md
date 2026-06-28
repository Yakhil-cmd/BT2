# Q1328: deploy_code() version split through fixed-address deployment routing in `CreateScheme::Fixed`

## Question
Can an attacker exploit a compatibility split around fixed-address deployment routing in `CreateScheme::Fixed` so one transaction form is accepted by one parser or branch and handled differently by another branch in `deploy_code()` on the Aurora engine contract, yielding Permanent freezing of funds?

## Target
- File/function: `engine/src/contract_methods/evm_transactions.rs::deploy_code -> engine/src/engine.rs::deploy_code_with_input / deploy_code` -> `fixed-address deployment routing in `CreateScheme::Fixed``
- Entrypoint: `deploy_code()` on the Aurora engine contract
- Attacker controls: deployment bytecode, constructor input, repeated deployment timing, and any address constraints reachable through the entry path
- Exploit idea: abuse typed-transaction or compatibility boundaries around the subtarget.
- Invariant to test: contract deployment must charge and commit exactly once, derive the correct address, and never leave half-deployed state behind
- Expected Immunefi impact: Permanent freezing of funds
- Fast validation: Run the same logical transaction through each reachable parsing branch and compare normalized fields, status, gas, and state changes. write a Rust integration test that deploys crafted bytecode through `deploy_code()`, then checks address derivation, code storage, logs, balances, and revert handling
