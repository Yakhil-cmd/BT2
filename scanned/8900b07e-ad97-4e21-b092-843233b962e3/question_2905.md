# Q2905: native exit precompiles identity forgery through recipient schema in `exit_to_eth_schema()`

## Question
Can an attacker make surrounding EVM code trust a forged account, promise, or environment identity returned by recipient schema in `exit_to_eth_schema()`, then move value or authorization it should not and cause Permanent freezing of funds?

## Target
- File/function: `engine-precompiles/src/native.rs + engine/src/contract_methods/connector.rs::exit_to_near_precompile_callback` -> `recipient schema in `exit_to_eth_schema()``
- Entrypoint: an EVM transaction submitted through `submit()`, `submit_with_args()`, `call()`, or `deploy_code()` that invokes the exit-to-NEAR or exit-to-Ethereum precompile
- Attacker controls: EVM calldata to the exit precompile, recipient bytes, amount, static-call context, repeated invocation timing, and revert behavior in the surrounding EVM call
- Exploit idea: abuse the semantics of the targeted environment-facing precompile output.
- Invariant to test: exit precompiles must burn, escrow, log, and callback exactly once for the intended asset and recipient
- Expected Immunefi impact: Permanent freezing of funds
- Fast validation: Cross-check the returned identity or environment value against the real runtime context under crafted call graphs. write integration tests that invoke the native exit precompiles from EVM code with crafted recipient and amount values, then inspect logs, refunds, and balances
