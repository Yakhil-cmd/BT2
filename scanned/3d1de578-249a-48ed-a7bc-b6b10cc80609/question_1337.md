# Q1337: deploy_code() log filter mismatch after fixed-address deployment routing in `CreateScheme::Fixed`

## Question
Can an attacker make fixed-address deployment routing in `CreateScheme::Fixed` emit logs or promise markers that the engine filters differently from the committed state, letting external systems or callbacks act on the wrong interpretation and eventually causing Temporary freezing of funds?

## Target
- File/function: `engine/src/contract_methods/evm_transactions.rs::deploy_code -> engine/src/engine.rs::deploy_code_with_input / deploy_code` -> `fixed-address deployment routing in `CreateScheme::Fixed``
- Entrypoint: `deploy_code()` on the Aurora engine contract
- Attacker controls: deployment bytecode, constructor input, repeated deployment timing, and any address constraints reachable through the entry path
- Exploit idea: exploit disagreement between emitted logs/promise markers and committed value movement around the subtarget.
- Invariant to test: contract deployment must charge and commit exactly once, derive the correct address, and never leave half-deployed state behind
- Expected Immunefi impact: Temporary freezing of funds
- Fast validation: Capture raw logs and filtered logs for crafted transactions and confirm they cannot imply value movement different from committed state. write a Rust integration test that deploys crafted bytecode through `deploy_code()`, then checks address derivation, code storage, logs, balances, and revert handling
