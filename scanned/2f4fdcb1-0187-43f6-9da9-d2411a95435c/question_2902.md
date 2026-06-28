# Q2902: native exit precompiles malformed-input success at recipient schema in `exit_to_eth_schema()`

## Question
Can an attacker feed malformed input through an EVM transaction submitted through `submit()`, `submit_with_args()`, `call()`, or `deploy_code()` that invokes the exit-to-NEAR or exit-to-Ethereum precompile so that recipient schema in `exit_to_eth_schema()` returns a successful-looking output instead of a clean rejection, letting surrounding contracts act on forged meaning and cause Temporary freezing of funds?

## Target
- File/function: `engine-precompiles/src/native.rs + engine/src/contract_methods/connector.rs::exit_to_near_precompile_callback` -> `recipient schema in `exit_to_eth_schema()``
- Entrypoint: an EVM transaction submitted through `submit()`, `submit_with_args()`, `call()`, or `deploy_code()` that invokes the exit-to-NEAR or exit-to-Ethereum precompile
- Attacker controls: EVM calldata to the exit precompile, recipient bytes, amount, static-call context, repeated invocation timing, and revert behavior in the surrounding EVM call
- Exploit idea: target malformed input that slips through validation at the precompile boundary.
- Invariant to test: exit precompiles must burn, escrow, log, and callback exactly once for the intended asset and recipient
- Expected Immunefi impact: Temporary freezing of funds
- Fast validation: Fuzz invalid lengths, padding, and field values and assert the precompile never returns a success output for malformed input. write integration tests that invoke the native exit precompiles from EVM code with crafted recipient and amount values, then inspect logs, refunds, and balances
