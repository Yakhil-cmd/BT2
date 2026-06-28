# Q2990: native exit precompiles resource amplification through behavior under static-call context

## Question
Can an attacker batch or repeat calls to behavior under static-call context through an EVM transaction submitted through `submit()`, `submit_with_args()`, `call()`, or `deploy_code()` that invokes the exit-to-NEAR or exit-to-Ethereum precompile so a small paid input expands into disproportionate CPU, memory, or promise work and causes Temporary freezing of funds?

## Target
- File/function: `engine-precompiles/src/native.rs + engine/src/contract_methods/connector.rs::exit_to_near_precompile_callback` -> `behavior under static-call context`
- Entrypoint: an EVM transaction submitted through `submit()`, `submit_with_args()`, `call()`, or `deploy_code()` that invokes the exit-to-NEAR or exit-to-Ethereum precompile
- Attacker controls: EVM calldata to the exit precompile, recipient bytes, amount, static-call context, repeated invocation timing, and revert behavior in the surrounding EVM call
- Exploit idea: amplify a per-call underpricing or allocation bug at the named precompile.
- Invariant to test: exit precompiles must burn, escrow, log, and callback exactly once for the intended asset and recipient
- Expected Immunefi impact: Temporary freezing of funds
- Fast validation: Run a high-count local sequence and compare cumulative paid gas with measured work and any resulting balance drain. write integration tests that invoke the native exit precompiles from EVM code with crafted recipient and amount values, then inspect logs, refunds, and balances
