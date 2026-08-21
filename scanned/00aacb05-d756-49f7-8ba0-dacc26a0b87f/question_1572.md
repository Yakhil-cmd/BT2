# Q1572: pipelining race in adapter::view_global_contract_code

## Question
Can an unprivileged attacker who deploys attacker-authored wasm with a `DeployContract` action and then calls it, controlling contract code that is prefetched and compiled while the account is redeployed, drive `runtime/runtime/src/adapter.rs::view_global_contract_code` to make the prepared contract differ from the code the receipt should execute, breaking the invariant that the code executed for a receipt is exactly the code stored at that account for that block, and leading to unintended permanent chain split requiring a hard fork?

## Target
- File/function: `runtime/runtime/src/adapter.rs` -> `view_global_contract_code`
- Entrypoint: unprivileged attacker deploys attacker-authored wasm with a `DeployContract` action and then calls it
- Attacker controls: contract code that is prefetched and compiled while the account is redeployed
- Exploit idea: make the prepared contract differ from the code the receipt should execute
- Invariant to test: the code executed for a receipt is exactly the code stored at that account for that block
- Expected Immunefi impact: Critical - unintended permanent chain split requiring a hard fork
- Fast validation: run the same chunk through both execution paths and assert identical state root, gas burnt and outcome ids
