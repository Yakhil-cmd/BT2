# Q1255: call() multi-tx amplification through log filtering and promise extraction after execution

## Question
Can an attacker batch or sequence many small transactions through `call()` on the Aurora engine contract so that log filtering and promise extraction after execution applies a rounding, caching, or accounting shortcut that compounds into Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield?

## Target
- File/function: `engine/src/contract_methods/evm_transactions.rs::call -> engine/src/engine.rs::call_with_args / call` -> `log filtering and promise extraction after execution`
- Entrypoint: `call()` on the Aurora engine contract
- Attacker controls: borsh `CallArgs`, target contract address, calldata, attached value, and repeated call ordering
- Exploit idea: amplify a per-call discrepancy at the subtarget across many user-controlled transactions.
- Invariant to test: direct EVM call entry must preserve the same balance, gas, authorization, and state-commit invariants as transaction submission
- Expected Immunefi impact: Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield
- Fast validation: Run a high-count local sequence with tiny value and gas variations, then compare cumulative balances and fees against expected totals. write a Rust integration test that invokes `call()` with crafted `CallArgs`, including edge-case values and calldata, and checks status, logs, balances, and storage
