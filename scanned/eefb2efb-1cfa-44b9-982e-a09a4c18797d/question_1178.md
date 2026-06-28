# Q1178: call() gas floor gap at value forwarding into `Engine::call`

## Question
Can an attacker use `call()` on the Aurora engine contract so that value forwarding into `Engine::call` enforces too little work relative to the real execution path, enabling underpriced execution that drains relayer or protocol balances and causes Insolvency?

## Target
- File/function: `engine/src/contract_methods/evm_transactions.rs::call -> engine/src/engine.rs::call_with_args / call` -> `value forwarding into `Engine::call``
- Entrypoint: `call()` on the Aurora engine contract
- Attacker controls: borsh `CallArgs`, target contract address, calldata, attached value, and repeated call ordering
- Exploit idea: undercharge work by targeting the floor or intrinsic-gas assumption baked into the subtarget.
- Invariant to test: direct EVM call entry must preserve the same balance, gas, authorization, and state-commit invariants as transaction submission
- Expected Immunefi impact: Insolvency
- Fast validation: Measure actual work against charged gas on crafted calldata and access-list sizes, then assert no path underpays for execution. write a Rust integration test that invokes `call()` with crafted `CallArgs`, including edge-case values and calldata, and checks status, logs, balances, and storage
