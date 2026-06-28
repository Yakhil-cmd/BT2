# Q1174: call() delegation gap at value forwarding into `Engine::call`

## Question
Can an attacker abuse delegated code or authorization semantics through `call()` on the Aurora engine contract so that value forwarding into `Engine::call` trusts the wrong code-bearing account state, enabling unauthorized value movement or Insolvency?

## Target
- File/function: `engine/src/contract_methods/evm_transactions.rs::call -> engine/src/engine.rs::call_with_args / call` -> `value forwarding into `Engine::call``
- Entrypoint: `call()` on the Aurora engine contract
- Attacker controls: borsh `CallArgs`, target contract address, calldata, attached value, and repeated call ordering
- Exploit idea: target delegated-account behavior and any code-presence assumptions at the subtarget.
- Invariant to test: direct EVM call entry must preserve the same balance, gas, authorization, and state-commit invariants as transaction submission
- Expected Immunefi impact: Insolvency
- Fast validation: Construct delegated and non-delegated sender states around the same logical call and assert auth, fee, and execution behavior stay consistent. write a Rust integration test that invokes `call()` with crafted `CallArgs`, including edge-case values and calldata, and checks status, logs, balances, and storage
