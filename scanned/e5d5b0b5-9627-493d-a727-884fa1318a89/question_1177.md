# Q1177: call() log filter mismatch after value forwarding into `Engine::call`

## Question
Can an attacker make value forwarding into `Engine::call` emit logs or promise markers that the engine filters differently from the committed state, letting external systems or callbacks act on the wrong interpretation and eventually causing Temporary freezing of funds?

## Target
- File/function: `engine/src/contract_methods/evm_transactions.rs::call -> engine/src/engine.rs::call_with_args / call` -> `value forwarding into `Engine::call``
- Entrypoint: `call()` on the Aurora engine contract
- Attacker controls: borsh `CallArgs`, target contract address, calldata, attached value, and repeated call ordering
- Exploit idea: exploit disagreement between emitted logs/promise markers and committed value movement around the subtarget.
- Invariant to test: direct EVM call entry must preserve the same balance, gas, authorization, and state-commit invariants as transaction submission
- Expected Immunefi impact: Temporary freezing of funds
- Fast validation: Capture raw logs and filtered logs for crafted transactions and confirm they cannot imply value movement different from committed state. write a Rust integration test that invokes `call()` with crafted `CallArgs`, including edge-case values and calldata, and checks status, logs, balances, and storage
