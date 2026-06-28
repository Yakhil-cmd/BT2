# Q3018: native exit precompiles cross-precompile confusion involving coupling between native exit logs and `exit_to_near_precompile_callback`

## Question
Can an attacker combine coupling between native exit logs and `exit_to_near_precompile_callback` with another reachable precompile through an EVM transaction submitted through `submit()`, `submit_with_args()`, `call()`, or `deploy_code()` that invokes the exit-to-NEAR or exit-to-Ethereum precompile so one precompile’s output is unsafe to trust as the other’s input, leading to Insolvency?

## Target
- File/function: `engine-precompiles/src/native.rs + engine/src/contract_methods/connector.rs::exit_to_near_precompile_callback` -> `coupling between native exit logs and `exit_to_near_precompile_callback``
- Entrypoint: an EVM transaction submitted through `submit()`, `submit_with_args()`, `call()`, or `deploy_code()` that invokes the exit-to-NEAR or exit-to-Ethereum precompile
- Attacker controls: EVM calldata to the exit precompile, recipient bytes, amount, static-call context, repeated invocation timing, and revert behavior in the surrounding EVM call
- Exploit idea: compose precompiles in a way that exposes a mismatch in validation or semantics around the targeted one.
- Invariant to test: exit precompiles must burn, escrow, log, and callback exactly once for the intended asset and recipient
- Expected Immunefi impact: Insolvency
- Fast validation: Chain the targeted precompile with its natural companion in EVM tests and assert composition cannot forge privileged meaning or underpriced work. write integration tests that invoke the native exit precompiles from EVM code with crafted recipient and amount values, then inspect logs, refunds, and balances
