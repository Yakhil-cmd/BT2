# Q2979: native exit precompiles supply coupling bug at amount handling for zero and extreme values

## Question
Can an attacker invoke amount handling for zero and extreme values so that token supply, bridge supply, or escrow supply coupled to the precompile drifts from the actual burned or minted amount, causing Temporary freezing of funds?

## Target
- File/function: `engine-precompiles/src/native.rs + engine/src/contract_methods/connector.rs::exit_to_near_precompile_callback` -> `amount handling for zero and extreme values`
- Entrypoint: an EVM transaction submitted through `submit()`, `submit_with_args()`, `call()`, or `deploy_code()` that invokes the exit-to-NEAR or exit-to-Ethereum precompile
- Attacker controls: EVM calldata to the exit precompile, recipient bytes, amount, static-call context, repeated invocation timing, and revert behavior in the surrounding EVM call
- Exploit idea: check how the targeted precompile’s output is coupled to supply-moving code.
- Invariant to test: exit precompiles must burn, escrow, log, and callback exactly once for the intended asset and recipient
- Expected Immunefi impact: Temporary freezing of funds
- Fast validation: Track total supply, escrowed balances, and recipient balances before and after the crafted call sequence. write integration tests that invoke the native exit precompiles from EVM code with crafted recipient and amount values, then inspect logs, refunds, and balances
