# Q2968: native exit precompiles output ambiguity from amount handling for zero and extreme values

## Question
Can an attacker craft input so that amount handling for zero and extreme values returns an output that multiple surrounding consumers could interpret differently, letting a caller treat a failure as success and cause Insolvency?

## Target
- File/function: `engine-precompiles/src/native.rs + engine/src/contract_methods/connector.rs::exit_to_near_precompile_callback` -> `amount handling for zero and extreme values`
- Entrypoint: an EVM transaction submitted through `submit()`, `submit_with_args()`, `call()`, or `deploy_code()` that invokes the exit-to-NEAR or exit-to-Ethereum precompile
- Attacker controls: EVM calldata to the exit precompile, recipient bytes, amount, static-call context, repeated invocation timing, and revert behavior in the surrounding EVM call
- Exploit idea: look for outputs whose meaning is not rigid enough for downstream code.
- Invariant to test: exit precompiles must burn, escrow, log, and callback exactly once for the intended asset and recipient
- Expected Immunefi impact: Insolvency
- Fast validation: Decode the precompile output through every reachable consumer path and ensure all interpretations agree. write integration tests that invoke the native exit precompiles from EVM code with crafted recipient and amount values, then inspect logs, refunds, and balances
