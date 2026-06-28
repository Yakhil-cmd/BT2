# Q3005: native exit precompiles identity forgery through coupling between native exit logs and `exit_to_near_precompile_callback`

## Question
Can an attacker make surrounding EVM code trust a forged account, promise, or environment identity returned by coupling between native exit logs and `exit_to_near_precompile_callback`, then move value or authorization it should not and cause Temporary freezing of funds?

## Target
- File/function: `engine-precompiles/src/native.rs + engine/src/contract_methods/connector.rs::exit_to_near_precompile_callback` -> `coupling between native exit logs and `exit_to_near_precompile_callback``
- Entrypoint: an EVM transaction submitted through `submit()`, `submit_with_args()`, `call()`, or `deploy_code()` that invokes the exit-to-NEAR or exit-to-Ethereum precompile
- Attacker controls: EVM calldata to the exit precompile, recipient bytes, amount, static-call context, repeated invocation timing, and revert behavior in the surrounding EVM call
- Exploit idea: abuse the semantics of the targeted environment-facing precompile output.
- Invariant to test: exit precompiles must burn, escrow, log, and callback exactly once for the intended asset and recipient
- Expected Immunefi impact: Temporary freezing of funds
- Fast validation: Cross-check the returned identity or environment value against the real runtime context under crafted call graphs. write integration tests that invoke the native exit precompiles from EVM code with crafted recipient and amount values, then inspect logs, refunds, and balances
