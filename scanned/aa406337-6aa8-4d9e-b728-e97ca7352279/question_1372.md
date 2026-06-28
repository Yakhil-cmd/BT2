# Q1372: deploy_code() pause or silo bypass through promise-log filtering after deployment

## Question
Can an attacker choose transaction shape or sender identity through `deploy_code()` on the Aurora engine contract so that promise-log filtering after deployment bypasses a pause, whitelist, or silo expectation that later execution assumes is enforced, producing Insolvency?

## Target
- File/function: `engine/src/contract_methods/evm_transactions.rs::deploy_code -> engine/src/engine.rs::deploy_code_with_input / deploy_code` -> `promise-log filtering after deployment`
- Entrypoint: `deploy_code()` on the Aurora engine contract
- Attacker controls: deployment bytecode, constructor input, repeated deployment timing, and any address constraints reachable through the entry path
- Exploit idea: use alternative sender, access-list, or typed-transaction paths to slip past the intended gate near the subtarget.
- Invariant to test: contract deployment must charge and commit exactly once, derive the correct address, and never leave half-deployed state behind
- Expected Immunefi impact: Insolvency
- Fast validation: Enable the relevant restriction in test state, then exercise alternate transaction forms and assert they are all rejected consistently. write a Rust integration test that deploys crafted bytecode through `deploy_code()`, then checks address derivation, code storage, logs, balances, and revert handling
