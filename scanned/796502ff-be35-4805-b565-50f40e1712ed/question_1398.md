# Q1398: deploy_code() gas floor gap at state application after create success or failure

## Question
Can an attacker use `deploy_code()` on the Aurora engine contract so that state application after create success or failure enforces too little work relative to the real execution path, enabling underpriced execution that drains relayer or protocol balances and causes Temporary freezing of funds?

## Target
- File/function: `engine/src/contract_methods/evm_transactions.rs::deploy_code -> engine/src/engine.rs::deploy_code_with_input / deploy_code` -> `state application after create success or failure`
- Entrypoint: `deploy_code()` on the Aurora engine contract
- Attacker controls: deployment bytecode, constructor input, repeated deployment timing, and any address constraints reachable through the entry path
- Exploit idea: undercharge work by targeting the floor or intrinsic-gas assumption baked into the subtarget.
- Invariant to test: contract deployment must charge and commit exactly once, derive the correct address, and never leave half-deployed state behind
- Expected Immunefi impact: Temporary freezing of funds
- Fast validation: Measure actual work against charged gas on crafted calldata and access-list sizes, then assert no path underpays for execution. write a Rust integration test that deploys crafted bytecode through `deploy_code()`, then checks address derivation, code storage, logs, balances, and revert handling
