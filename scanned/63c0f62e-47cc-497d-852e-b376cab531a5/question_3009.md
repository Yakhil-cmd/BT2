# Q3009: native exit precompiles revert-versus-success split in coupling between native exit logs and `exit_to_near_precompile_callback`

## Question
Can an attacker make coupling between native exit logs and `exit_to_near_precompile_callback` turn what should be a reverting path into a successful return with sentinel bytes, or vice versa, so the surrounding engine violates exit precompiles must burn, escrow, log, and callback exactly once for the intended asset and recipient and causes Temporary freezing of funds?

## Target
- File/function: `engine-precompiles/src/native.rs + engine/src/contract_methods/connector.rs::exit_to_near_precompile_callback` -> `coupling between native exit logs and `exit_to_near_precompile_callback``
- Entrypoint: an EVM transaction submitted through `submit()`, `submit_with_args()`, `call()`, or `deploy_code()` that invokes the exit-to-NEAR or exit-to-Ethereum precompile
- Attacker controls: EVM calldata to the exit precompile, recipient bytes, amount, static-call context, repeated invocation timing, and revert behavior in the surrounding EVM call
- Exploit idea: split failure signaling from actual effect at the targeted precompile.
- Invariant to test: exit precompiles must burn, escrow, log, and callback exactly once for the intended asset and recipient
- Expected Immunefi impact: Temporary freezing of funds
- Fast validation: Enumerate malformed and edge-case inputs and compare exit status with any returned bytes, logs, and state effects. write integration tests that invoke the native exit precompiles from EVM code with crafted recipient and amount values, then inspect logs, refunds, and balances
