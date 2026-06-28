# Q2971: native exit precompiles address aliasing around amount handling for zero and extreme values

## Question
Can an attacker reach amount handling for zero and extreme values through an aliased or unexpected precompile address under an EVM transaction submitted through `submit()`, `submit_with_args()`, `call()`, or `deploy_code()` that invokes the exit-to-NEAR or exit-to-Ethereum precompile, bypassing the address-specific assumptions of surrounding code and causing Temporary freezing of funds?

## Target
- File/function: `engine-precompiles/src/native.rs + engine/src/contract_methods/connector.rs::exit_to_near_precompile_callback` -> `amount handling for zero and extreme values`
- Entrypoint: an EVM transaction submitted through `submit()`, `submit_with_args()`, `call()`, or `deploy_code()` that invokes the exit-to-NEAR or exit-to-Ethereum precompile
- Attacker controls: EVM calldata to the exit precompile, recipient bytes, amount, static-call context, repeated invocation timing, and revert behavior in the surrounding EVM call
- Exploit idea: look for address-level confusion in the precompile set or downstream consumers.
- Invariant to test: exit precompiles must burn, escrow, log, and callback exactly once for the intended asset and recipient
- Expected Immunefi impact: Temporary freezing of funds
- Fast validation: Probe all configured precompile addresses and confirm only the intended address family reaches the targeted logic. write integration tests that invoke the native exit precompiles from EVM code with crafted recipient and amount values, then inspect logs, refunds, and balances
