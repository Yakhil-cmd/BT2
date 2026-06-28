# Q1134: call() delegation gap at borsh decoding of `CallArgs`

## Question
Can an attacker abuse delegated code or authorization semantics through `call()` on the Aurora engine contract so that borsh decoding of `CallArgs` trusts the wrong code-bearing account state, enabling unauthorized value movement or Permanent freezing of funds?

## Target
- File/function: `engine/src/contract_methods/evm_transactions.rs::call -> engine/src/engine.rs::call_with_args / call` -> `borsh decoding of `CallArgs``
- Entrypoint: `call()` on the Aurora engine contract
- Attacker controls: borsh `CallArgs`, target contract address, calldata, attached value, and repeated call ordering
- Exploit idea: target delegated-account behavior and any code-presence assumptions at the subtarget.
- Invariant to test: direct EVM call entry must preserve the same balance, gas, authorization, and state-commit invariants as transaction submission
- Expected Immunefi impact: Permanent freezing of funds
- Fast validation: Construct delegated and non-delegated sender states around the same logical call and assert auth, fee, and execution behavior stay consistent. write a Rust integration test that invokes `call()` with crafted `CallArgs`, including edge-case values and calldata, and checks status, logs, balances, and storage
