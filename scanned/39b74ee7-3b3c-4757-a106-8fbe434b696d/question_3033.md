# Q3033: native exit precompiles cost recording gap after address selection for the exit precompile account

## Question
Can an attacker cause address selection for the exit precompile account to complete useful work while `post_process` or `record_cost` accounts for too little of it, leading to Insolvency?

## Target
- File/function: `engine-precompiles/src/native.rs + engine/src/contract_methods/connector.rs::exit_to_near_precompile_callback` -> `address selection for the exit precompile account`
- Entrypoint: an EVM transaction submitted through `submit()`, `submit_with_args()`, `call()`, or `deploy_code()` that invokes the exit-to-NEAR or exit-to-Ethereum precompile
- Attacker controls: EVM calldata to the exit precompile, recipient bytes, amount, static-call context, repeated invocation timing, and revert behavior in the surrounding EVM call
- Exploit idea: split useful work from the gas-recording phase after the targeted precompile.
- Invariant to test: exit precompiles must burn, escrow, log, and callback exactly once for the intended asset and recipient
- Expected Immunefi impact: Insolvency
- Fast validation: Instrument precompile execution and confirm every successful path records the full charged cost before returning. write integration tests that invoke the native exit precompiles from EVM code with crafted recipient and amount values, then inspect logs, refunds, and balances
