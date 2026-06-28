# Q2913: native exit precompiles cost recording gap after recipient schema in `exit_to_eth_schema()`

## Question
Can an attacker cause recipient schema in `exit_to_eth_schema()` to complete useful work while `post_process` or `record_cost` accounts for too little of it, leading to Permanent freezing of funds?

## Target
- File/function: `engine-precompiles/src/native.rs + engine/src/contract_methods/connector.rs::exit_to_near_precompile_callback` -> `recipient schema in `exit_to_eth_schema()``
- Entrypoint: an EVM transaction submitted through `submit()`, `submit_with_args()`, `call()`, or `deploy_code()` that invokes the exit-to-NEAR or exit-to-Ethereum precompile
- Attacker controls: EVM calldata to the exit precompile, recipient bytes, amount, static-call context, repeated invocation timing, and revert behavior in the surrounding EVM call
- Exploit idea: split useful work from the gas-recording phase after the targeted precompile.
- Invariant to test: exit precompiles must burn, escrow, log, and callback exactly once for the intended asset and recipient
- Expected Immunefi impact: Permanent freezing of funds
- Fast validation: Instrument precompile execution and confirm every successful path records the full charged cost before returning. write integration tests that invoke the native exit precompiles from EVM code with crafted recipient and amount values, then inspect logs, refunds, and balances
