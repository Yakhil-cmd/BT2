# Q2936: native exit precompiles promise side-effect order near event encoding for exit logs

## Question
Can an attacker make event encoding for exit logs emit logs, promise requests, or other side effects before the final error condition is known, leaving an exploitable mismatch that causes Permanent freezing of funds?

## Target
- File/function: `engine-precompiles/src/native.rs + engine/src/contract_methods/connector.rs::exit_to_near_precompile_callback` -> `event encoding for exit logs`
- Entrypoint: an EVM transaction submitted through `submit()`, `submit_with_args()`, `call()`, or `deploy_code()` that invokes the exit-to-NEAR or exit-to-Ethereum precompile
- Attacker controls: EVM calldata to the exit precompile, recipient bytes, amount, static-call context, repeated invocation timing, and revert behavior in the surrounding EVM call
- Exploit idea: seek a side effect that escapes before the targeted precompile’s final validity check.
- Invariant to test: exit precompiles must burn, escrow, log, and callback exactly once for the intended asset and recipient
- Expected Immunefi impact: Permanent freezing of funds
- Fast validation: Force the last failing condition after any intermediate side effect and assert nothing externally visible survives. write integration tests that invoke the native exit precompiles from EVM code with crafted recipient and amount values, then inspect logs, refunds, and balances
