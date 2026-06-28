# Q2997: native exit precompiles determinism gap in behavior under static-call context

## Question
Can an attacker trigger behavior under static-call context with the same logical input under two equivalent public entry conditions and obtain different outputs, costs, or state effects, eventually causing Permanent freezing of funds?

## Target
- File/function: `engine-precompiles/src/native.rs + engine/src/contract_methods/connector.rs::exit_to_near_precompile_callback` -> `behavior under static-call context`
- Entrypoint: an EVM transaction submitted through `submit()`, `submit_with_args()`, `call()`, or `deploy_code()` that invokes the exit-to-NEAR or exit-to-Ethereum precompile
- Attacker controls: EVM calldata to the exit precompile, recipient bytes, amount, static-call context, repeated invocation timing, and revert behavior in the surrounding EVM call
- Exploit idea: look for non-deterministic behavior at the targeted precompile boundary.
- Invariant to test: exit precompiles must burn, escrow, log, and callback exactly once for the intended asset and recipient
- Expected Immunefi impact: Permanent freezing of funds
- Fast validation: Replay equivalent calls under identical state and assert output bytes, logs, and charged gas are deterministic. write integration tests that invoke the native exit precompiles from EVM code with crafted recipient and amount values, then inspect logs, refunds, and balances
